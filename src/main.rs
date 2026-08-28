//! Headless IDA Pro MCP Server
//!
//! This binary runs an MCP server that provides headless IDA Pro access
//! via stdin/stdout transport.
//!
//! Architecture:
//! - Main thread: Runs IDA worker loop (IDA requires main thread)
//! - Background thread: Runs tokio runtime with async MCP server

use axum::{routing::get, Router};
use clap::{Args, Parser, Subcommand};
use ida_mcp::idalib::{idb::IDBOpenOptions, Address, IDB};
use ida_mcp::server::http_sessions::build_pooled_session_manager;
use ida_mcp::server::task::TaskRegistry;
use ida_mcp::server::tool_filter::native_policy;
use ida_mcp::server::SanitizedIdaServer;
use ida_mcp::supervisor::{
    Capped, LegacySseConfig, LegacySseService, OutputCache, SessionManager, SupervisorServer,
};
use ida_mcp::{
    disasm::generate_disasm_line,
    expand_path, ida,
    ida::pool::{WorkerPool, WorkerPoolConfig},
    idalib, DbInfo, FunctionInfo, IdaMcpServer, IdaWorker, ServerMode,
};
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::ServiceExt;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};
use vibrev_kit::policy::{PolicyArgs, ToolPolicy};
use vibrev_kit::session::SessionArgs;

const REQUEST_QUEUE_CAPACITY: usize = 64;

#[derive(Parser)]
#[command(
    name = "ida-headless-mcp",
    version,
    about = "Headless IDA Pro MCP Server"
)]
struct Cli {
    #[command(flatten)]
    ida_network: IdaNetworkArgs,
    /// Enable arbitrary-code and stateful diff tools.
    #[arg(
        long = "unsafe",
        env = "IDA_MCP_UNSAFE",
        global = true,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    unsafe_tools: bool,
    /// Maximum simultaneous IDA database worker processes.
    #[arg(
        long = "max-databases",
        env = "IDA_MCP_MAX_WORKERS",
        default_value = "4",
        global = true
    )]
    max_databases: NonZeroUsize,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the MCP server (default)
    Serve,
    /// Run the MCP server over Streamable HTTP (SSE)
    ServeHttp(ServeHttpArgs),
    /// Run a child worker for the HTTP process pool
    #[command(hide = true)]
    Worker(WorkerArgs),
    /// Run a direct CLI probe to exercise idalib
    Probe(ProbeArgs),
    /// Inspect and export the agent skills built into this binary
    Skills(vibrev_skills::SkillsArgs),
}

// Tool filter flags. Defined at the top level with `global = true` so they
// work on the default stdio invocation (`ida-mcp --toolsets=core`) as well
// as on `ida-mcp serve …` and `ida-mcp serve-http …`.
//
// Compose order (locked): no include flags → all tools; otherwise the
// union of `--toolsets` and `--tools`; then `--exclude-tools`; then
// `--read-only`. Flags override env vars.
/// The tool-selection flags, from `vibrev-kit` with this engine's env vars on top.
///
/// The names, the help text, the comma splitting and the composition order are
/// the kit's, so that this engine and `bn-headless-mcp` cannot drift on what
/// `--read-only` means. The `IDA_MCP_*` variables are ours and predate the kit,
/// so they are added here rather than pushed down: an env var is a name in the
/// user's shell, and kit has no business inventing one per engine.
fn policy_args() -> Vec<clap::Arg> {
    use vibrev_kit::policy::{EXCLUDE_TOOLS_ARG, READ_ONLY_ARG, TOOLSETS_ARG, TOOLS_ARG};
    PolicyArgs::args()
        .into_iter()
        .map(|arg| {
            let env = match arg.get_id().as_str() {
                TOOLSETS_ARG => "IDA_MCP_TOOLSETS",
                TOOLS_ARG => "IDA_MCP_TOOLS",
                EXCLUDE_TOOLS_ARG => "IDA_MCP_EXCLUDE_TOOLS",
                READ_ONLY_ARG => "IDA_MCP_READ_ONLY",
                other => unreachable!("kit added a policy flag this engine has not named: {other}"),
            };
            let arg = arg.env(env);
            // `--read-only` is an `ArgAction::SetTrue` flag, and clap runs an
            // env var's *value* through the parser that action implies — which
            // accepts only "true"/"false". `IDA_MCP_READ_ONLY=1` is the natural
            // spelling in a client config (it is what `IDA_MCP_ALLOW_LUMINA`
            // below takes), and without this parser it fails the process at
            // startup. Adding the parser here rather than in the kit keeps this
            // an env-var concern, which is the same reason `.env()` is applied
            // here in the first place.
            if arg.get_id() == READ_ONLY_ARG {
                arg.value_parser(clap::builder::BoolishValueParser::new())
            } else {
                arg
            }
        })
        .collect()
}

#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "IDA network")]
struct IdaNetworkArgs {
    /// Allow IDA to contact configured Lumina servers.
    #[arg(
        long,
        env = "IDA_MCP_ALLOW_LUMINA",
        global = true,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    allow_lumina: bool,
}

impl IdaNetworkArgs {
    fn worker_args(&self) -> Vec<OsString> {
        if self.allow_lumina {
            vec![OsString::from("--allow-lumina")]
        } else {
            Vec::new()
        }
    }
}

/// The pool knobs. Everything about the *listener* — bind, token, Origin/Host,
/// framing, body cap — comes from `vibrev_kit::transport::HttpOptions`, which
/// [`http_options`] hangs on this subcommand as plain `Arg`s. Those are shared
/// with `bn-headless-mcp` so that two engines cannot spell `--bind` two ways;
/// the five below are about child IDA processes and belong to this engine.
#[derive(Args)]
struct ServeHttpArgs {
    /// Maximum child worker processes the HTTP pool may run. Each open database
    /// holds one for its whole session, so this also caps concurrent databases:
    /// past it, idb_open fails rather than queueing.
    #[arg(long, default_value_t = 4)]
    max_workers: usize,
    /// Minimum idle child worker processes to keep warm in pooled mode.
    #[arg(long, default_value_t = 0)]
    min_workers: usize,
    /// Seconds before an idle pooled worker is reaped (0 disables reaping).
    #[arg(long, default_value_t = 300)]
    worker_idle_timeout_secs: u64,
    /// Per-child operation watchdog in seconds; the parent kills a child that
    /// exceeds it. This is a wedged-process safety net, not a UX deadline.
    #[arg(long, default_value_t = 1800)]
    worker_op_timeout_secs: u64,
    /// Grace period before pooled sessions are closed after a client stream disconnects.
    #[arg(long, default_value_t = 2)]
    worker_disconnect_grace_secs: u64,
}

#[derive(Args)]
struct WorkerArgs {}

#[derive(Args)]
struct ProbeArgs {
    /// Path to the .i64/.idb database
    #[arg(long)]
    path: String,
    /// Output .i64/.idb path when opening a raw binary (defaults to <path>.i64)
    #[arg(long)]
    idb_out: Option<String>,
    /// Force auto-analysis (default: on for raw binaries, off for .i64/.idb)
    #[arg(long)]
    auto_analyse: bool,
    /// List the first N functions (optional)
    #[arg(long)]
    list: Option<usize>,
    /// Resolve a function name (optional)
    #[arg(long)]
    resolve: Option<String>,
    /// Disassemble a function by name (optional)
    #[arg(long)]
    disasm_by_name: Option<String>,
    /// Disassemble at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    disasm_addr: Option<String>,
    /// Decompile a function at an address (hex 0x... or decimal, optional)
    #[arg(long)]
    decompile_addr: Option<String>,
    /// Instruction count for disassembly (default: 20)
    #[arg(long, default_value_t = 20)]
    count: usize,
    /// Enable IDA console messages (may be verbose)
    #[arg(long)]
    ida_console: bool,
}

/// The root-level commands this engine handles itself.
///
/// The kit checks every derived tool name against exactly this list, so it has
/// to match the `Command` enum above rather than the kit's `RESERVED` guess —
/// which names `serve` and `mcp` and `status` and knows nothing about
/// `serve-http`, `worker` or `probe`.
const MANAGEMENT_COMMANDS: &[&str] = &["serve", "serve-http", "worker", "probe", "skills"];

/// The one command that opens a listener, named once so `cli_command` and
/// `main` cannot disagree about where the kit's flags were hung.
const SERVE_HTTP_COMMAND: &str = "serve-http";

/// Graft the derived tool tree onto the derive-generated root.
///
/// Two clap idioms meet here: this binary's own commands come from `#[derive(Parser)]`,
/// and the tool subtree is built by the kit from the same `Tool` structs the MCP
/// surface publishes. `Cli::command()` is the bridge — the derived tree hangs off
/// it as one more subcommand, and every global flag (`--toolsets`, `--unsafe`, …)
/// keeps working on both sides.
/// The listener flags, from `vibrev-kit` with this engine's env var on top.
///
/// Same arrangement as [`policy_args`], for the same reason: the kit owns the
/// names, the help and the defaults so `bn-headless-mcp` cannot spell them
/// differently, and `IDA_MCP_TOKEN_FILE` is ours and predates the kit.
fn http_options() -> Vec<clap::Arg> {
    vibrev_kit::transport::HttpOptions::args()
        .into_iter()
        .map(|arg| {
            match arg.get_id().as_str() {
                id if id == vibrev_kit::transport::TOKEN_FILE_ARG => arg.env("IDA_MCP_TOKEN_FILE"),
                // Host checking is off unless the operator asks for it. The
                // check exists to stop DNS rebinding — a page in a browser
                // resolving a name it controls to 127.0.0.1 and talking to this
                // listener. What actually stops that here is the bearer token,
                // which is unconditional and which such a page has no way to
                // read. Leaving the Host check on as well mostly rejects
                // legitimate setups behind a reverse proxy or a container DNS
                // name, so it is opt-in: name the hosts to turn it back on.
                id if id == vibrev_kit::transport::ALLOW_HOST_ARG => arg.default_value("*"),
                _ => arg,
            }
        })
        .collect()
}

fn cli_command() -> clap::Command {
    let derived = IdaMcpServer::vibrev_cli("ida-headless-mcp")
        .with_management(MANAGEMENT_COMMANDS)
        .with_session(&ida_mcp::server::SESSION)
        .command();
    let tools = derived
        .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
        .expect("the kit always builds a `tool` subcommand")
        .clone();
    let cmd = <Cli as clap::CommandFactory>::command()
        .args(policy_args())
        .mut_subcommand(SERVE_HTTP_COMMAND, |serve_http| {
            serve_http.args(http_options())
        })
        .subcommand(tools);
    // `with_management` only feeds the collision check, which runs before this
    // Parser tree is grafted on. The closed loop is here: declared names and
    // the finished clap root must agree.
    vibrev_kit::cli::assert_management_matches_command(&cmd, MANAGEMENT_COMMANDS);
    cmd
}

fn main() -> anyhow::Result<()> {
    // Initialize logging to stderr (stdout is used for MCP protocol)
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("ida_mcp=info")))
        .init();

    let matches = cli_command().get_matches();
    // Read before the `resolve` early-return: that branch never reaches
    // `Cli::from_arg_matches`, and the flags are `global(true)` on every level.
    let selection = PolicyArgs::read(&matches);
    // Anything under `tool` is a derived tool; everything else at the root is
    // one of this engine's own commands and falls through untouched.
    if let Some((name, leaf)) = vibrev_kit::cli::resolve(&matches) {
        return run_tool_cli(name, leaf);
    }

    let cli = <Cli as clap::FromArgMatches>::from_arg_matches(&matches)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Filter is only used by the MCP server paths. Probe doesn't load any
    // tools, so don't reject probe runs because a bad IDA_MCP_TOOLSETS is
    // sitting in the inherited env from a sibling mcpServers.json config.
    let build_filter = || {
        native_policy(&selection)
            .map(Arc::new)
            .map_err(|e| anyhow::anyhow!("invalid tool filter: {e}"))
    };
    let build_supervisor_filter = || {
        let policy = ida_mcp::supervisor::supervisor_policy(&selection)
            .map_err(|e| anyhow::anyhow!("invalid supervisor tool filter: {e}"))?;
        // The unsafe gate is a second door this engine keeps outside the policy;
        // only their interaction can leave the catalog empty.
        ida_mcp::supervisor::validate_unsafe_gate(&policy, cli.unsafe_tools)
            .map_err(|e| anyhow::anyhow!("invalid supervisor tool filter: {e}"))?;
        Ok::<_, anyhow::Error>(Arc::new(policy))
    };
    let allow_lumina = cli.ida_network.allow_lumina;
    let worker_args = cli.ida_network.worker_args();
    let unsafe_tools = cli.unsafe_tools;
    let max_workers = cli.max_databases.get();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => run_supervisor_stdio(
            max_workers,
            unsafe_tools,
            build_supervisor_filter()?,
            worker_args,
        ),
        Command::ServeHttp(args) => {
            // The listener flags live on the subcommand, not the root: they mean
            // nothing to `serve` or `tool`, so unlike the policy flags they are
            // not `global(true)` and have to be read from that level.
            let http = vibrev_kit::transport::HttpOptions::read(
                matches
                    .subcommand_matches(SERVE_HTTP_COMMAND)
                    .expect("this arm was reached through that subcommand"),
            );
            run_supervisor_http(
                args,
                http,
                unsafe_tools,
                build_supervisor_filter()?,
                worker_args,
            )
        }
        Command::Worker(_args) => {
            run_server_with_mode(build_filter()?, ServerMode::Worker, allow_lumina)
        }
        Command::Probe(args) => run_probe(args, allow_lumina),
        Command::Skills(args) => run_skills(args),
    }
}

/// `skills list` / `skills export`.
///
/// Deliberately never reaches `run_ida_loop`: the answer is baked into the
/// binary, so demanding a database — or a license — to read it would make the
/// command useless in exactly the situation it exists for, which is an
/// installer inspecting an engine it has just found on disk.
///
/// The verbs themselves are `vibrev_skills`, shared with every other engine and
/// with the installer that parses their output. The engine's name and version
/// are passed in because that crate must not report its own.
fn run_skills(args: vibrev_skills::SkillsArgs) -> anyhow::Result<()> {
    args.run(
        &ida_mcp::skills::SKILLS,
        ida_mcp::SERVER_NAME,
        env!("CARGO_PKG_VERSION"),
    )
}

/// Run one derived tool and exit.
///
/// Same shape as `run_server_with_mode`: IDA owns the main thread, so the tool
/// call happens on a background thread's runtime and this one goes straight into
/// `run_ida_loop`. The difference is that there is exactly one call and then the
/// worker is shut down.
fn run_tool_cli(name: String, leaf: &clap::ArgMatches) -> anyhow::Result<()> {
    let defs = IdaMcpServer::vibrev_tool_defs();
    let Some(def) = defs.iter().find(|d| d.name() == name) else {
        anyhow::bail!("unknown tool: {name}");
    };

    // `--json-input` carries whatever the flags cannot express. No IDA tool
    // currently needs it — none has an object-typed parameter — but the branch
    // is the kit's contract, not this engine's.
    let args = match leaf.try_get_one::<String>("__json_input").ok().flatten() {
        Some(path) => {
            let raw = if path == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(path)?
            };
            serde_json::from_str(&raw)?
        }
        None => match vibrev_kit::cli::to_arguments(def, leaf) {
            Ok(value) => value,
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(2);
            }
        },
    };

    // `None` for the handful of tools that answer out of the catalog or out of
    // arithmetic; they never reach the worker, so demanding a database would be
    // a requirement the tool does not have.
    let session = match ida_mcp::server::SESSION.read_for(def, leaf) {
        Ok(session) => session,
        Err(missing) => {
            eprintln!("Error: {missing}");
            std::process::exit(2);
        }
    };
    let as_json = leaf.get_flag("__json");

    let init_state = init_stdio_ida_state(false)?;
    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let backend = Arc::new(IdaWorker::new(tx));
    let backend_for_call = backend.clone();

    let call = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create tokio runtime: {e}"))?;
        rt.block_on(async move {
            let outcome =
                call_one_tool(&backend_for_call, session.as_ref(), &name, args, as_json).await;
            shutdown_worker_bounded(&backend_for_call).await;
            outcome
        })
    });

    ida::run_ida_loop(rx, init_state);

    match call.join() {
        Ok(Ok(code)) => std::process::exit(code),
        Ok(Err(e)) => {
            // The CLI reports through exit code + stderr, never by printing an
            // error object on stdout.
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        Err(e) => Err(anyhow::anyhow!("tool thread panicked: {e:?}")),
    }
}

/// Open the database, run the tool, print the result. Returns the exit code.
async fn call_one_tool(
    backend: &Arc<IdaWorker>,
    session: Option<&SessionArgs>,
    name: &str,
    args: serde_json::Value,
    as_json: bool,
) -> anyhow::Result<i32> {
    if let Some(session) = session {
        let idb = session.target.as_str();
        backend
            .open_observed(
                ida_mcp::OpenSpec {
                    path: idb.to_string(),
                    auto_analyse: true,
                    ..Default::default()
                },
                Some(600),
                None,
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("open {idb}: {}", with_lock_advice(&e.to_string())))?;

        // The readiness gate the kit owns and this engine answers. `auto_state`
        // is not usable for the question — it reads `AU_NONE` throughout — so
        // the probe is `auto_is_ok`. Giving up is *said*, not just logged: a
        // result taken before analysis settles is well-formed, smaller and
        // wrong, and nothing in the payload of a tool that owes no
        // `analysis_coverage` contradicts it.
        if session.wait_for_ready
            && let Some(ready) = &ida_mcp::server::SESSION.ready
        {
            let outcome = vibrev_kit::session::wait_until_ready(ready, || async {
                backend
                    .analysis_status()
                    .await
                    .map(|status| status.auto_is_ok)
                    .map_err(|e| e.to_string())
            })
            .await;
            if let Some(warning) = outcome.warning(ready) {
                warn!("{warning}");
                eprintln!("{warning}");
            }
        }
    }

    let server = IdaMcpServer::with_filter(
        backend.clone(),
        ServerMode::Worker,
        Arc::new(ToolPolicy::unrestricted()),
    );

    // The same function body `tools/call` reaches, through the same
    // `IntoCallToolResult` the MCP router converts with.
    let outcome = server
        .vibrev_call(name, args)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e.message))?;

    let text = if as_json {
        outcome.json_text()
    } else {
        outcome.text.clone()
    };
    if outcome.is_error {
        // The tool ran and reported failure: `isError: true` over MCP, exit
        // code + stderr here. Collapsing the two would make the CLI disagree
        // with the MCP surface about what happened.
        eprintln!("{text}");
        return Ok(1);
    }
    println!("{text}");
    Ok(0)
}

/// Turn the lock conflict into something the person at the terminal can act on.
///
/// `--idb` takes the database's `.imcp` lock, and the common way to hit that is
/// the *good* case: an MCP server is already analysing this database for an
/// agent, and the user wants a quick look from a shell. Refusing is correct —
/// two IDA processes on one database corrupt it — but the bare error names a
/// lock file and a pid and stops there, which reads as a malfunction rather than
/// as "that database is busy". The CLI cannot attach to the running session
/// (`--idb` opens and owns; there is no cross-process handle to a supervisor
/// session), so the honest advice is the three things that do work.
fn with_lock_advice(error: &str) -> String {
    if !error.contains("open in another instance") {
        return error.to_owned();
    }
    format!(
        "{error}\n\
         提示：该数据库已被另一个进程独占（上面括号里是它的 pid）。CLI 的 --idb 是\
         「打开并独占」，无法连接到已在运行的会话，所以可选：\n  \
         1) 通过那个 MCP 服务器调用同名工具；\n  \
         2) 结束该进程（或让它 close_idb / idb_close）后重试；\n  \
         3) 复制一份数据库，对副本用 --idb。"
    )
}

/// Resolve when the process is asked to stop.
///
/// `vibrev_kit::transport` owns the signal set because the listener it serves
/// has to honour the same one; this alias keeps the stdio path — which has no
/// listener — reading the way it always did.
async fn wait_for_shutdown_signal() {
    vibrev_kit::transport::shutdown_signal().await;
}

fn init_stdio_ida_state(allow_lumina: bool) -> anyhow::Result<ida::IdaInitState> {
    // On Windows, IDA's init_library() probes console handles during
    // startup. In stdio mode the MCP transport captures stdin/stdout
    // for JSON-RPC framing, so init must run *before* the transport
    // starts — otherwise init_library() deadlocks on the owned handle.
    #[cfg(target_os = "windows")]
    {
        ida::init_ida_library(allow_lumina)
            .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        ida::IdaInitState::deferred(allow_lumina)
            .map_err(|e| anyhow::anyhow!("IDA startup preparation failed: {e}"))
    }
}

/// Bounded worker shutdown. If IDA is wedged inside auto_wait() these
/// requests sit behind it and the process can stay alive indefinitely
/// (issue #32). After the timeout we forcibly exit so the OS reclaims
/// IDA's mmap'd memory regardless. 124 matches GNU `timeout`'s "did its
/// best, timed out" convention.
async fn shutdown_worker_bounded(worker: &Arc<IdaWorker>) {
    const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
    let close_result =
        tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, worker.close_for_shutdown()).await;
    let shutdown_result = tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, worker.shutdown()).await;
    if close_result.is_err() || shutdown_result.is_err() {
        warn!(
            timeout_secs = WORKER_SHUTDOWN_TIMEOUT.as_secs(),
            close_timed_out = close_result.is_err(),
            shutdown_timed_out = shutdown_result.is_err(),
            "IDA worker shutdown timed out (likely wedged in auto_wait); \
             forcing process exit to release IDA-side memory"
        );
        std::process::exit(124);
    }
}

fn cancel_background_tasks(registry: &TaskRegistry, message: &str) {
    let requested = registry.cancel_all_running(message);
    if requested > 0 {
        info!(
            cancellation_requests = requested,
            message, "Requested background task cancellation"
        );
    }
}

fn run_supervisor_stdio(
    max_workers: usize,
    unsafe_tools: bool,
    filter: Arc<ToolPolicy>,
    worker_args: Vec<OsString>,
) -> anyhow::Result<()> {
    info!(
        max_workers,
        unsafe_tools, "Starting explicit multi-database supervisor on stdio"
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("failed to create tokio runtime: {error}"))?;

    runtime.block_on(async move {
        let exe_path = std::env::current_exe()
            .map_err(|error| anyhow::anyhow!("failed to resolve current executable: {error}"))?;
        let pool = WorkerPool::new(WorkerPoolConfig {
            max_workers,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(1800),
            exe_path,
            worker_args,
        });
        let sessions = SessionManager::new(pool);
        sessions.start_idle_reaper();
        // Files rather than a URL: stdio has no listener to fetch from, and the
        // client started this process, so it can read what this process writes.
        let output_cache = OutputCache::spilling_to_files("ida-headless-mcp")
            .map_err(|error| anyhow::anyhow!("failed to initialize output storage: {error}"))?;
        let server = Capped::new(
            SupervisorServer::new(sessions.clone(), unsafe_tools, filter),
            output_cache,
        );
        let mut service = server
            .serve(stdio())
            .await
            .map_err(|error| anyhow::anyhow!("stdio MCP negotiation failed: {error}"))?;
        let shutdown = Arc::new(Notify::new());
        let signal = shutdown.clone();
        tokio::spawn(async move {
            wait_for_shutdown_signal().await;
            signal.notify_one();
        });

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    let _ = service.close_with_timeout(Duration::from_secs(2)).await?;
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(200)) => {
                    if service.is_transport_closed() {
                        let _ = service.close_with_timeout(Duration::from_secs(2)).await?;
                        break;
                    }
                }
            }
        }
        sessions.shutdown().await;
        Ok(())
    })
}

fn run_server_with_mode(
    filter: Arc<ToolPolicy>,
    mode: ServerMode,
    allow_lumina: bool,
) -> anyhow::Result<()> {
    info!(?mode, "Starting IDA MCP Server (stdio transport)");
    let init_state = init_stdio_ida_state(allow_lumina)?;

    // Create channel for IDA requests
    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE_CAPACITY);
    let worker = IdaWorker::new(tx);
    let backend = Arc::new(worker.clone());

    // Spawn background thread for tokio runtime and MCP server
    let worker_for_server = backend.clone();
    let worker_for_shutdown = backend.clone();
    let filter_for_server = filter.clone();
    let server_handle = thread::spawn(move || {
        // Create tokio runtime on this background thread
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create tokio runtime: {e}"))?;

        rt.block_on(async move {
            info!("MCP server listening on stdio");
            let server = IdaMcpServer::with_filter(
                worker_for_server,
                mode,
                filter_for_server.clone(),
            );
            let task_registry = server.task_registry().clone();
            let sanitized = SanitizedIdaServer::with_filter(server, filter_for_server);
            let mut service = match sanitized.serve(stdio()).await {
                Ok(running) => Some(running),
                Err(e) => {
                    // rmcp fails the serve future without answering the client
                    // when the first message is not a valid initialize/discover
                    // request. Shut the IDA worker down so the process exits
                    // instead of wedging with an unread stdin.
                    error!(error = %e, "stdio MCP negotiation failed; shutting down IDA worker");
                    shutdown_worker_bounded(&worker_for_shutdown).await;
                    return Err(anyhow::anyhow!("stdio MCP negotiation failed: {e}"));
                }
            };
            let shutdown_notify = Arc::new(Notify::new());
            let shutdown_signal = shutdown_notify.clone();

            let shutdown_tasks = task_registry.clone();
            tokio::spawn(async move {
                wait_for_shutdown_signal().await;
                info!("Shutdown signal received");
                cancel_background_tasks(&shutdown_tasks, "Cancelled by server shutdown");
                shutdown_signal.notify_one();
            });

            loop {
                tokio::select! {
                    _ = shutdown_notify.notified() => {
                        cancel_background_tasks(
                            &task_registry,
                            "Cancelled by server shutdown",
                        );
                        if let Some(mut running) = service.take() {
                            let _ = running.close().await?;
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if let Some(running) = service.as_ref()
                            && running.is_transport_closed()
                        {
                            cancel_background_tasks(
                                &task_registry,
                                "Cancelled by client disconnect",
                            );
                            if let Some(mut running) = service.take()
                                && running
                                    .close_with_timeout(Duration::from_secs(2))
                                    .await?
                                    .is_none()
                            {
                                warn!(
                                    "Timed out waiting for stdio transport cleanup after client disconnect"
                                );
                            }
                            break;
                        }
                    }
                }
            }
            info!("MCP server shutting down");
            shutdown_worker_bounded(&worker_for_shutdown).await;
            Ok::<_, anyhow::Error>(())
        })
    });

    // Run IDA worker loop on the main thread after startup preflight.
    info!("Starting IDA worker loop");
    ida::run_ida_loop(rx, init_state);
    info!("IDA worker loop finished");

    // Wait for server thread to finish
    // Propagate server-thread failures (e.g. stdio negotiation errors) into
    // the process exit status so supervisors can tell them from clean shutdown.
    match server_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("Server thread failed: {e}");
            return Err(e);
        }
        Err(e) => {
            error!("Server thread panicked: {:?}", e);
            return Err(anyhow::anyhow!("server thread panicked: {e:?}"));
        }
    }

    info!("Server stopped");
    Ok(())
}

/// What a caller holding the token reaches through this port.
///
/// The kit refuses to serve without a credential but has no opinion about which
/// tools sit behind the port; the obligation it puts in place of hiding them is
/// this — say plainly what the port is worth to whoever gets the token.
fn exposure(unsafe_tools: bool) -> vibrev_kit::transport::Exposure {
    vibrev_kit::transport::Exposure {
        engine: "ida-headless-mcp",
        routes: &["/mcp", "/sse", "/output/"],
        reach: vec![
            "a caller holding the token can open any file on this host as a \
             database (reading arbitrary files is what this tool does)"
                .to_string(),
        ],
        arbitrary_code: unsafe_tools.then(|| {
            "--unsafe is on, so run_script/py_eval/py_exec_file are reachable".to_string()
        }),
    }
}

fn run_supervisor_http(
    args: ServeHttpArgs,
    http: vibrev_kit::transport::HttpOptions,
    unsafe_tools: bool,
    filter: Arc<ToolPolicy>,
    worker_args: Vec<OsString>,
) -> anyhow::Result<()> {
    if args.max_workers == 0 {
        return Err(anyhow::anyhow!("--max-workers must be at least 1"));
    }
    if args.min_workers > args.max_workers {
        return Err(anyhow::anyhow!(
            "--min-workers ({}) cannot exceed --max-workers ({})",
            args.min_workers,
            args.max_workers
        ));
    }
    if args.worker_op_timeout_secs == 0 {
        return Err(anyhow::anyhow!(
            "--worker-op-timeout-secs must be at least 1"
        ));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow::anyhow!("failed to create tokio runtime: {error}"))?;

    runtime.block_on(async move {
        // Establishes the credential before it binds, so a token we cannot read
        // does not leave a port open while the error is reported.
        let listener = vibrev_kit::transport::Listener::bind(&http).await?;
        let listen_addr = listener.addr();
        // Straight to stderr, not through `tracing`: an inherited
        // RUST_LOG=error must not be able to swallow what this listener does
        // and does not let through.
        eprintln!(
            "{}",
            listener.banner(&exposure(unsafe_tools), std::io::stderr().is_terminal())
        );
        for note in listener.token_notes() {
            eprintln!(" {note}");
        }
        let exe_path = std::env::current_exe()
            .map_err(|error| anyhow::anyhow!("failed to resolve current executable: {error}"))?;
        let pool = WorkerPool::new(WorkerPoolConfig {
            max_workers: args.max_workers,
            min_workers: args.min_workers,
            worker_idle_timeout: Duration::from_secs(args.worker_idle_timeout_secs),
            worker_op_timeout: Duration::from_secs(args.worker_op_timeout_secs),
            exe_path,
            worker_args,
        });
        pool.warm_min()
            .await
            .map_err(|error| anyhow::anyhow!("failed to warm worker pool: {error}"))?;
        let sessions = SessionManager::new(pool);
        sessions.start_idle_reaper();
        let output_addr = if listen_addr.ip().is_unspecified() {
            if listen_addr.is_ipv4() {
                SocketAddr::from(([127, 0, 0, 1], listen_addr.port()))
            } else {
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], listen_addr.port()))
            }
        } else {
            listen_addr
        };
        let output_cache = OutputCache::http(format!("http://{output_addr}"));
        let http_sessions = build_pooled_session_manager(
            http.session_keep_alive_secs,
            Duration::from_secs(args.worker_disconnect_grace_secs),
        );
        let cancel = listener.cancel().clone();
        let config = listener.config().clone();
        let sessions_for_factory = sessions.clone();
        let filter_for_factory = filter.clone();
        let output_cache_for_factory = output_cache.clone();
        let service = StreamableHttpService::new(
            move || {
                Ok(Capped::new(
                    SupervisorServer::new(
                        sessions_for_factory.clone(),
                        unsafe_tools,
                        filter_for_factory.clone(),
                    ),
                    output_cache_for_factory.clone(),
                ))
            },
            http_sessions,
            config,
        );
        let legacy_sessions = sessions.clone();
        let legacy_filter = filter.clone();
        let legacy_output_cache = output_cache.clone();
        let legacy_service = LegacySseService::new(
            move || {
                Capped::new(
                    SupervisorServer::new(
                        legacy_sessions.clone(),
                        unsafe_tools,
                        legacy_filter.clone(),
                    ),
                    legacy_output_cache.clone(),
                )
            },
            LegacySseConfig::new(
                (http.sse_keep_alive_secs != 0)
                    .then(|| Duration::from_secs(http.sse_keep_alive_secs)),
                http.max_request_body_mib.saturating_mul(1024 * 1024),
                cancel.clone(),
            ),
        );
        // No `.layer(...)` here, and that is the point: the kit takes the whole
        // router and puts the gate over all of it, so `/output/` — added after
        // `/mcp`, and a second way to read the same tool results — cannot be
        // left uncovered by an oversight at this call site.
        let router = Router::new()
            .route_service("/mcp", service)
            .route_service("/sse", legacy_service)
            .route(
                "/output/{*id}",
                get(ida_mcp::supervisor::output::serve_output),
            )
            .with_state(output_cache);
        info!("MCP supervisor listening on http://{listen_addr}/mcp and /sse");

        listener.serve(router).await?;
        sessions.shutdown().await;
        Ok(())
    })
}

fn run_probe(args: ProbeArgs, allow_lumina: bool) -> anyhow::Result<()> {
    info!("Starting IDA MCP Server (probe mode)");
    if let Ok(idadir) = std::env::var("IDADIR") {
        info!("IDADIR={}", idadir);
    }
    info!("Initializing IDA library on main thread");
    let _init_state = ida::init_ida_library(allow_lumina)
        .map_err(|e| anyhow::anyhow!("IDA library initialization failed: {e}"))?;
    info!("IDA library initialized successfully");
    if let Ok(ver) = idalib::version() {
        info!(
            "IDA version {}.{}.{}",
            ver.major(),
            ver.minor(),
            ver.build()
        );
    }
    if args.ida_console {
        #[cfg(feature = "ida-92")]
        idalib::enable_console_messages(true);
        #[cfg(not(feature = "ida-92"))]
        idalib::enable_console_messages(true)
            .map_err(|e| anyhow::anyhow!("failed to enable console messages: {e}"))?;
        info!("IDA console messages enabled");
    }

    let path = expand_path(&args.path);
    info!("Opening database: {}", path.display());

    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();
    let path_display = path.display().to_string();
    let ticker = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(10));
            if done_clone.load(Ordering::Relaxed) {
                break;
            }
            info!(
                path = %path_display,
                elapsed = start.elapsed().as_secs(),
                "Still opening database..."
            );
        }
    });

    let open_start = Instant::now();
    let db = open_db_for_probe(&path, &args);
    done.store(true, Ordering::Relaxed);
    let _ = ticker.join();
    let db =
        db.map_err(|e| anyhow::anyhow!("Failed to open database: {}: {}", path.display(), e))?;

    let meta = db.meta();
    let info = DbInfo {
        path: path.display().to_string(),
        file_type: format!("{:?}", meta.filetype()),
        processor: db.processor().long_name(),
        bits: if meta.is_64bit() {
            64
        } else if meta.is_32bit_exactly() {
            32
        } else {
            16
        },
        function_count: db.function_count(),
        debug_info: None,
        analysis_status: ida::handlers::analysis::build_analysis_status(&db),
    };
    info!("Database opened in {}s", open_start.elapsed().as_secs());
    println!("{}", serde_json::to_string_pretty(&info)?);

    if let Some(limit) = args.list {
        let list = list_functions(&db, 0, limit);
        println!("{}", serde_json::to_string_pretty(&list)?);
    }

    if let Some(name) = args.resolve.as_deref() {
        let func = resolve_function(&db, name)?;
        println!("{}", serde_json::to_string_pretty(&func)?);
    }

    if let Some(name) = args.disasm_by_name.as_deref() {
        let text = disasm_by_name(&db, name, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.disasm_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let text = disasm_at(&db, addr, args.count)?;
        println!("{}", text);
    }

    if let Some(addr_str) = args.decompile_addr.as_deref() {
        let addr = parse_address(addr_str)?;
        let func = db
            .function_at(addr)
            .ok_or_else(|| anyhow::anyhow!("Function not found at address {:#x}", addr))?;
        if !db.decompiler_available() {
            return Err(anyhow::anyhow!("Decompiler not available"));
        }
        let cfunc = db
            .decompile(&func)
            .map_err(|e| anyhow::anyhow!("Decompile failed: {}", e))?;
        println!("{}", cfunc.pseudocode());
    }

    info!("Probe completed");
    Ok(())
}

fn open_db_for_probe(path: &PathBuf, args: &ProbeArgs) -> Result<IDB, idalib::IDAError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_idb = ext == "i64" || ext == "idb" || ext == "id0";
    let init_args = probe_init_database_args();

    if is_idb {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(args.auto_analyse).save(true);
        for arg in &init_args {
            opts.arg(arg);
        }
        if args.auto_analyse {
            info!("Opening existing IDB with auto-analysis enabled");
        }
        opts.open(path)
    } else {
        let mut opts = IDBOpenOptions::new();
        opts.auto_analyse(true);
        let out_path = if let Some(out) = args.idb_out.as_deref() {
            PathBuf::from(out)
        } else {
            ida_mcp::ida::handlers::database::idb_path_for_raw_binary(path)
        };
        info!(
            "Opening raw binary with auto-analysis (idb_out={})",
            out_path.display()
        );
        for arg in &init_args {
            opts.arg(arg);
        }
        opts.idb(&out_path).save(true).open(path)
    }
}

fn probe_init_database_args() -> Vec<String> {
    vec!["-A".to_string()]
}

fn parse_address(s: &str) -> anyhow::Result<u64> {
    Ok(ida_mcp::address::parse_address(s)?)
}

fn list_functions(db: &IDB, offset: usize, limit: usize) -> ida_mcp::FunctionListResult {
    let total = db.function_count();
    let mut functions = Vec::with_capacity(limit.min(total.saturating_sub(offset)));

    for (idx, (_id, func)) in db.functions().enumerate() {
        if idx < offset {
            continue;
        }
        if functions.len() >= limit {
            break;
        }

        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
        let size = func.len();

        functions.push(FunctionInfo {
            address: format!("{:#x}", addr),
            name,
            size,
        });
    }

    // Was `offset + functions.len()`, unsaturated: the one copy of this
    // arithmetic that could overflow on a wire-supplied offset.
    let next_offset = vibrev_kit::page::next_offset(offset, functions.len(), total);

    ida_mcp::FunctionListResult {
        functions,
        total,
        next_offset,
    }
}

fn resolve_function(db: &IDB, name: &str) -> anyhow::Result<FunctionInfo> {
    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name()
            && (func_name == name || func_name.contains(name))
        {
            let addr = func.start_address();
            let size = func.len();
            return Ok(FunctionInfo {
                address: format!("{:#x}", addr),
                name: func_name,
                size,
            });
        }
    }

    Err(anyhow::anyhow!("Function not found: {}", name))
}

fn disasm_by_name(db: &IDB, name: &str, count: usize) -> anyhow::Result<String> {
    let func = resolve_function(db, name)?;
    let addr = parse_address(&func.address)?;
    disasm_at(db, addr, count)
}

fn disasm_at(db: &IDB, addr: Address, count: usize) -> anyhow::Result<String> {
    let mut lines = Vec::with_capacity(count);
    let mut current_addr: Address = addr;

    for _ in 0..count {
        if let Some(line) = generate_disasm_line(db, current_addr) {
            lines.push(format!("{:#x}:\t{}", current_addr, line));
        } else {
            break;
        }

        if let Some(insn) = db.insn_at(current_addr) {
            current_addr += insn.len() as u64;
        } else if let Some(next) = db.next_head(current_addr) {
            if next <= current_addr {
                break;
            }
            current_addr = next;
        } else {
            break;
        }
    }

    if lines.is_empty() {
        return Err(anyhow::anyhow!("Address out of range: {:#x}", addr));
    }

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use crate::{cli_command, Cli};
    use clap::Parser;
    use std::ffi::OsString;
    use vibrev_kit::policy::PolicyArgs;

    /// The listener flags are the kit's and hang on this subcommand, so this
    /// goes through the real command tree: `Cli::parse_from` never sees them,
    /// and a wiring mistake in `cli_command` is exactly what would make
    /// `HttpOptions::read` fall back to defaults that only *look* right.
    #[test]
    fn the_listener_flags_reach_the_subcommand_that_uses_them() {
        let matches = cli_command().get_matches_from([
            "ida-mcp",
            "serve-http",
            "--bind",
            "127.0.0.1:19999",
            "--allow-host",
            "ida-box.local",
        ]);
        let leaf = matches
            .subcommand_matches(crate::SERVE_HTTP_COMMAND)
            .expect("serve-http matches");
        let http = vibrev_kit::transport::HttpOptions::read(leaf);
        assert_eq!(http.bind.to_string(), "127.0.0.1:19999");
        assert_eq!(http.allow_host, Some(vec!["ida-box.local".to_string()]));
        // rmcp's 300s default kills a long analysis mid-call; the kit's is what
        // this engine has always used.
        assert_eq!(http.session_keep_alive_secs, 1800);

        let crate::Command::ServeHttp(args) =
            <Cli as clap::FromArgMatches>::from_arg_matches(&matches)
                .expect("root parses")
                .command
                .expect("subcommand")
        else {
            panic!("expected serve-http")
        };
        assert_eq!(args.worker_disconnect_grace_secs, 2);
    }

    /// The listener has no off switch, and this is the level a user would look
    /// for one at. `vibrev-kit` has the same assertion over its own `Arg`s;
    /// this one covers the grafting, which is where such a flag would have to
    /// be reintroduced to take effect.
    #[test]
    fn serve_http_offers_no_way_to_drop_the_credential() {
        let mut command = cli_command();
        let rendered = command
            .find_subcommand_mut(crate::SERVE_HTTP_COMMAND)
            .expect("serve-http")
            .render_long_help()
            .to_string();
        for absent in ["--no-auth", "--insecure", "--anonymous", "--no-token"] {
            assert!(!rendered.contains(absent), "{absent} is offered");
        }
        assert!(rendered.contains("--token-file"));
    }

    #[test]
    fn lumina_access_is_disabled_by_default() {
        let cli = Cli::parse_from(["ida-mcp", "serve"]);

        assert!(!cli.ida_network.allow_lumina);
        assert!(cli.ida_network.worker_args().is_empty());
    }

    #[test]
    fn lumina_access_can_be_enabled_globally() {
        let before_subcommand = Cli::parse_from(["ida-mcp", "--allow-lumina", "worker"]);
        let after_subcommand = Cli::parse_from(["ida-mcp", "worker", "--allow-lumina"]);

        assert!(before_subcommand.ida_network.allow_lumina);
        assert!(after_subcommand.ida_network.allow_lumina);
        let worker_args = vec![OsString::from("--allow-lumina")];
        assert_eq!(before_subcommand.ida_network.worker_args(), worker_args);
    }

    /// The flags live on the builder side, so this goes through the real
    /// command tree rather than `Cli::parse_from` — which is what a user hits
    /// anyway, and the only way to see the `global(true)` propagation.
    #[test]
    fn global_filter_flags_build_the_supervisor_filter() {
        let matches = cli_command().get_matches_from(["ida-mcp", "--toolsets=decompile", "serve"]);
        let policy = ida_mcp::supervisor::supervisor_policy(&PolicyArgs::read(&matches))
            .expect("supervisor policy");

        assert!(policy.allows("decompile"));
        assert!(!policy.allows("patch"));
        // `idb_open` survives a narrow toolset selection even though `core` is
        // not among them: a supervisor that cannot open a database advertises
        // tools that can only answer "no database open".
        assert!(policy.allows("idb_open"));
    }

    #[test]
    fn unsafe_only_supervisor_filter_requires_unsafe_mode() {
        let selection = |args: [&str; 3]| PolicyArgs::read(&cli_command().get_matches_from(args));

        let safe = ida_mcp::supervisor::supervisor_policy(&selection([
            "ida-mcp",
            "--tools=run_script",
            "serve",
        ]))
        .expect("policy");
        assert!(ida_mcp::supervisor::validate_unsafe_gate(&safe, false).is_err());
        assert!(ida_mcp::supervisor::validate_unsafe_gate(&safe, true).is_ok());
    }

    /// The session flags are `global(true)` over the whole tool subtree, so a
    /// tool parameter spelling the same long would be defined twice and clap
    /// would keep one without saying which.
    ///
    /// The kit panics on this, but only over the tools that have been migrated —
    /// so assert it over all 82 published schemas and all 288 parameters
    /// instead, which is the population the check will eventually see. Measured
    /// rather than assumed: a guard that only ever runs over a handful of names
    /// says nothing about the surface it is supposed to protect.
    #[test]
    fn no_published_parameter_spells_a_session_flag() {
        let reserved: Vec<String> = std::iter::once(ida_mcp::server::SESSION.flag.to_string())
            .chain(
                ida_mcp::server::SESSION
                    .ready
                    .as_ref()
                    .map(|r| r.skip_flag.to_string()),
            )
            .collect();
        assert_eq!(reserved, ["idb", "no-wait-analysis"]);

        let mut checked = 0usize;
        let mut colliding: Vec<String> = Vec::new();
        for tool in ida_mcp::server::catalog::native_tools() {
            let Some(props) = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
            else {
                continue;
            };
            for name in props.keys() {
                checked += 1;
                let kebab = name.replace('_', "-");
                // Booleans also claim the hidden `--no-x` half of their pair.
                for flag in [kebab.clone(), format!("no-{kebab}")] {
                    if reserved.contains(&flag) {
                        colliding.push(format!("{}.{name} -> --{flag}", tool.name));
                    }
                }
            }
        }
        assert_eq!(checked, 397, "the parameter population changed");
        assert!(
            colliding.is_empty(),
            "these parameters would shadow a session flag: {colliding:?}"
        );
    }

    /// …and the check is not vacuous: a parameter really would be refused.
    #[test]
    #[should_panic(expected = "会话标志冲突：`--idb`")]
    fn a_parameter_named_idb_would_be_refused() {
        let schema: serde_json::Map<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "type": "object",
                "properties": { "idb": {"type": "string"} },
            }))
            .expect("an object schema is an object");
        let def = vibrev_kit::ToolDef {
            tool: rmcp::model::Tool::new("open", "test", schema),
            cli: vibrev_kit::CliHints {
                positional: &[],
                int_args: &[],
                enabled: true,
                needs_session: true,
            },
            ext: None,
        };
        let _ = vibrev_kit::cli::EngineCli::new("ida-headless-mcp", vec![def])
            .with_management(crate::MANAGEMENT_COMMANDS)
            .with_session(&ida_mcp::server::SESSION)
            .command();
    }
}
