//! MCP server implementation with IDA Pro tools.

pub(crate) mod address;
mod bytes;
mod classify;
mod parse;
mod script_outcome;
pub(crate) use crate::ida::handlers::controlflow::cyclomatic_complexity;
pub(crate) use bytes::*;
pub(crate) use classify::*;
pub(crate) use parse::*;
pub(crate) use script_outcome::*;
pub mod catalog;
pub mod http_sessions;
mod operation;
mod requests;
pub mod responses;
pub mod tool_filter;

/// The background-task registry and its SEP-2663 face: [`vibrev_kit::tasks`].
///
/// MCP Tasks is a protocol capability, not a disassembler capability: nothing
/// in the registry, the ownership rules or the retention window knows what an
/// `.i64` is. What lives here is the part that does — which tools go to the
/// background, and how *this* server resolves a task's owner from the
/// transport it arrived on (see the `TaskHost` impl below).
///
/// Aliased rather than imported name by name so the several hundred call sites
/// can go on reading `task::TaskRegistry`.
pub use vibrev_kit::tasks as task;

pub use address::AddressArg;
pub use requests::*;

use crate::error::ToolError;
use crate::ida::int_spec::IntSpec;
use crate::ida::leftover;
use crate::ida::observability::{ProgressReceiver, ProgressSender};
use crate::ida::query::{FunctionQuery, NameQuery, StringQuery, StringSearch, XrefQuery};
use crate::ida::request::SdkMutation;
use crate::ida::types::{ConditionalCloseResult, DatabaseGeneration};
use crate::ida::worker::{CloseAuthorization, CloseTokenGrant, IdaWorker, MAX_TIMEOUT_SECS};
use crate::server::catalog::ToolCategory;
// The tool policy is `vibrev-kit`'s; `tool_filter` supplies only this engine's
// taxonomy and its lifecycle list.
use crate::server::operation::{
    next_operation_id, OperationRegistry, OperationSnapshot, RecentOperations,
};
use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        tool::{InputResponses as ToolInputResponses, RequestState, ToolCallContext},
        wrapper::Parameters,
    },
    model::{
        CallToolResult, ContentBlock as Content, ServerCapabilities, ServerInfo, Tool,
        ToolAnnotations,
    },
    tool, tool_handler, ErrorData as McpError, ServerHandler,
};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};
use vibrev_kit::policy::ToolPolicy;
use vibrev_kit::session::{ReadySpec, SessionSpec};
use vibrev_kit::tasks::{call_tool_result_to_value, TaskHost};
use vibrev_tool_macros::vibrev_tool_router;

pub(crate) struct SessionLifetime {
    cancel: tokio_util::sync::CancellationToken,
}

/// State that must survive across handler instances created for stateless MCP
/// requests. Long-lived transports use one value per handler; single-worker
/// HTTP shares one value across legacy sessions and modern sessionless requests
/// because they all operate on the same IDA context.
#[derive(Clone)]
pub struct ServerRuntimeState {
    task_registry: task::TaskRegistry,
    operation_registry: OperationRegistry,
    operation_nonce: Arc<AtomicU64>,
    /// Parent lifetime for background tasks spawned by sessionless MCP 2026
    /// requests, whose handlers drop as soon as the response is sent. Cancelled
    /// only when the runtime state itself drops (process/transport shutdown).
    runtime_lifetime: Arc<SessionLifetime>,
    request_state_codec: rmcp::model::RequestStateCodec,
    /// True when the HTTP transport runs with `--stateless`: rmcp then builds
    /// a fresh handler per request even for legacy protocol versions, so every
    /// request must use the shared runtime task owner and lifetime — otherwise
    /// a legacy client's background task would be cancelled when its handler
    /// drops and owned by a session identity that never recurs.
    stateless_http: bool,
}

impl Default for ServerRuntimeState {
    fn default() -> Self {
        let signing_key = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        Self {
            task_registry: task::TaskRegistry::new(),
            operation_registry: OperationRegistry::new(),
            operation_nonce: Arc::new(AtomicU64::new(0)),
            runtime_lifetime: Arc::new(SessionLifetime::new()),
            // `try_new` rejects a key under `MIN_KEY_LENGTH` (32). Two hyphenated
            // v4 UUIDs are 72 bytes, so the only way this fails is someone
            // shortening the line above — which is exactly when a panic here is
            // the right answer, because a short key silently weakens every sealed
            // request state.
            request_state_codec: rmcp::model::RequestStateCodec::try_new(signing_key.into_bytes())
                .expect("two v4 UUIDs are 72 bytes, well over MIN_KEY_LENGTH"),
            stateless_http: false,
        }
    }
}

impl ServerRuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runtime state for an HTTP transport started with `--stateless` (see
    /// [`Self::stateless_http`]).
    pub fn new_stateless_http() -> Self {
        Self {
            stateless_http: true,
            ..Self::default()
        }
    }
}

impl SessionLifetime {
    fn new() -> Self {
        Self {
            cancel: tokio_util::sync::CancellationToken::new(),
        }
    }

    fn child_token(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.child_token()
    }
}

impl Drop for SessionLifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// MCP server for IDA Pro analysis
#[derive(Clone)]
pub struct IdaMcpServer {
    worker: Arc<IdaWorker>,
    tool_mux: ToolMux<IdaMcpServer>,
    mode: ServerMode,
    task_registry: task::TaskRegistry,
    operation_registry: OperationRegistry,
    operation_nonce: Arc<AtomicU64>,
    /// Shared runtime lifetime (see [`ServerRuntimeState::runtime_lifetime`]).
    runtime_lifetime: Arc<SessionLifetime>,
    /// Per-handler lifetime. rmcp keeps a legacy session's handler alive for
    /// the whole session and drops it on session close, so background tasks
    /// parented here are cancelled when their legacy session ends. Sessionless
    /// MCP 2026 handlers drop per request, so their background tasks must use
    /// `runtime_lifetime` instead (see [`Self::background_lifetime`]).
    session_lifetime: Arc<SessionLifetime>,
    request_state_codec: rmcp::model::RequestStateCodec,
    /// Unique ID for this handler context. It is stable for a legacy session,
    /// while sessionless MCP 2026 HTTP creates a fresh value per request. It is
    /// also the ownership identity used by the legacy HTTP close-token path.
    session_id: String,
    /// Stable task owner for requests served through this handler. Sessionless
    /// MCP 2026 requests instead use the shared runtime owner.
    session_task_owner: task::TaskOwner,
    /// See [`ServerRuntimeState::stateless_http`].
    stateless_http: bool,
    /// Server-side tool filter (applied to tools/list, tools/call, and
    /// surfaced via tool_catalog / tool_help).
    filter: Arc<ToolPolicy>,
}

#[derive(Clone, Copy, Debug)]
pub enum ServerMode {
    Stdio,
    Http,
    Worker,
}

#[derive(Clone)]
pub(crate) struct ToolMux<S> {
    call_router: ToolRouter<S>,
}

impl<S> ToolMux<S>
where
    S: Send + Sync + 'static,
{
    fn new(call_router: ToolRouter<S>) -> Self {
        Self { call_router }
    }

    fn list_all(&self) -> Vec<Tool> {
        self.call_router
            .list_all()
            .into_iter()
            .map(apply_tool_metadata)
            .collect()
    }

    fn get(&self, name: &str) -> Option<&Tool> {
        self.call_router.map.get(name).map(|route| &route.attr)
    }
}

/// What this engine's tools are *about*.
///
/// Every one of the 82 reads the open database, and none of them says so in its
/// own schema — the supervisor injects a `database` selector into the copies it
/// routes, the worker has exactly one open and takes no parameter at all. So the
/// value has to come from somewhere the schema is not, and that somewhere is
/// declared here rather than assembled from string literals at the call site:
/// the flag, its help, and the sentence printed when it is missing are one
/// object, and the kit removes `database` from the derived flags so it cannot
/// come to mean two things.
///
/// `--idb` *opens* a database and owns it for the one call. It is not an attach:
/// a supervisor session belongs to a running server and there is no way to reach
/// it from a separate process, so pretending the flag covered both would be a
/// lie the first `--idb sess-abc123` would expose.
pub const SESSION: SessionSpec = SessionSpec {
    selector: Some("database"),
    flag: "idb",
    value_name: "PATH",
    help: "要打开的 .i64/.idb 或原始二进制（工具在它上面执行）",
    missing: "IDA 的每个工具都读当前打开的数据库，而 CLI 是一次性进程，必须先知道打开哪个。\
              注意这是「打开并独占」，不是连接到正在运行的 MCP 服务器的会话。",
    ready: Some(ReadySpec {
        skip_flag: "no-wait-analysis",
        skip_help: "跳过等待 auto_is_ok；未收敛的数据库会返回看似合理的不完整数据",
        // `open_idb` itself is capped at 600s; matching it keeps the two halves
        // of one command from disagreeing about how long is too long.
        timeout: Duration::from_secs(600),
        poll: Duration::from_millis(200),
        timed_out: "警告：等待自动分析收敛超时，下面的结果可能是不完整的（计数偏小、xref 缺失）。\
                    用 analysis_status 确认，或对大型二进制先跑 analyze_funcs。",
        unknown: "警告：无法确认自动分析是否已收敛，下面的结果可能是不完整的",
    }),
};

/// Tools whose handlers consume MRTR `requestState`/`inputResponses`. Other
/// tools must reject those fields instead of silently executing a fresh call.
pub(crate) const MRTR_AWARE_TOOLS: &[&str] = &["open_idb"];

/// True when a request carries the complete MCP 2026 inline-metadata key set.
/// rmcp routes such requests through the sessionless per-request path
/// regardless of the protocol version the metadata declares (`is_legacy_request`,
/// tower.rs), so this is the authoritative "which handler lifetime am I running
/// under" predicate on HTTP transports.
pub(crate) fn is_sessionless_request_meta(meta: &rmcp::model::RequestMetaObject) -> bool {
    meta.missing_required_keys(&ProtocolVersion::V_2026_07_28)
        .is_empty()
}

impl ToolMux<IdaMcpServer> {
    async fn call(
        &self,
        context: ToolCallContext<'_, IdaMcpServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        if !MRTR_AWARE_TOOLS.contains(&context.name())
            && (context.request_state.is_some() || context.input_responses.is_some())
        {
            return Err(McpError::invalid_params(
                format!(
                    "tool '{}' does not accept requestState/inputResponses",
                    context.name()
                ),
                None,
            ));
        }
        // `open_dsc` is the engine's half of the decision — the one tool here
        // whose answer is a handle rather than a result. Whether the peer can
        // hold that handle is the protocol's half, and the kit owns it.
        let should_materialize_task = context.name() == "open_dsc"
            && task::peer_can_hold_task_handle(
                context.request_context().protocol_version(),
                context.request_context().client_capabilities(),
            );
        // Copied out before the router consumes `context`: the promotion needs
        // the server, and `service` is a shared reference, not a borrow of the
        // context itself.
        let host = context.service;
        let response = self.call_router.call(context).await?;
        host.materialize_task_response(should_materialize_task, response)
    }
}

/// Parameters for the background DSC loading task.
pub(crate) struct DscBackgroundCtx {
    open: DscBackgroundOpen,
    module: String,
    frameworks: Vec<String>,
    owner_session_id: Option<String>,
}

pub(crate) enum DscBackgroundOpen {
    DirectRawDsc {
        open_path: std::path::PathBuf,
        idb_out: std::path::PathBuf,
    },
    LegacyIdat {
        idat: std::path::PathBuf,
        idat_args: Vec<String>,
        script_path: std::path::PathBuf,
        log_path: Option<std::path::PathBuf>,
        out_i64: std::path::PathBuf,
    },
}

pub(crate) struct TemporaryFileCleanup {
    path: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DscOpenPlan {
    DirectExistingI64,
    BackgroundDirectRawDsc,
    LegacyIdatBackground,
}

pub(crate) fn dsc_open_plan(sdk_version: (i32, i32), i64_exists: bool) -> DscOpenPlan {
    // An existing database wins on every SDK: reopening it preserves prior
    // analysis (renames, comments, loaded modules) and skips the load. On 9.4
    // that database is the deterministic direct-path cache or a legacy
    // sibling; pre-9.4 it is the sibling idat produced.
    if i64_exists {
        DscOpenPlan::DirectExistingI64
    } else if sdk_version >= (9, 4) {
        DscOpenPlan::BackgroundDirectRawDsc
    } else {
        DscOpenPlan::LegacyIdatBackground
    }
}

pub(crate) fn sanitize_temp_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        "dsc".to_string()
    } else {
        sanitized
    }
}

/// Deterministic per-DSC database location for the IDA 9.4 direct open path.
///
/// DSCs commonly sit on read-only mounts, so the generated database cannot
/// reliably live next to them the way the legacy idat path's sibling `.i64`
/// does. Deriving the name from the absolute DSC path — never pid or time —
/// means every `open_dsc` of the same cache resolves to one file: repeat opens
/// reuse the analyzed database (with any renames/comments) instead of leaking
/// a fresh multi-GB orphan per call.
pub(crate) fn direct_dsc_cache_i64_path(dsc_path: &std::path::Path) -> std::path::PathBuf {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let absolute = dsc_path
        .canonicalize()
        .unwrap_or_else(|_| dsc_path.to_path_buf());
    let name = absolute
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_temp_component)
        .unwrap_or_else(|| "dsc".to_string());
    let mut hasher = DefaultHasher::new();
    absolute.hash(&mut hasher);
    let hash = hasher.finish();
    std::env::temp_dir().join(format!("ida-mcp-dsc-{name}-{hash:016x}.i64"))
}

impl TemporaryFileCleanup {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn cleanup_now(&mut self) {
        if let Some(path) = self.path.take() {
            remove_temporary_file(&path);
        }
    }
}

impl Drop for TemporaryFileCleanup {
    fn drop(&mut self) {
        self.cleanup_now();
    }
}

pub(crate) fn remove_temporary_file(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => warn!(
            path = %path.display(),
            error = %err,
            "failed to remove temporary file"
        ),
    }
}

/// Inputs above this size automatically route `open_idb(auto_analyse=true)`
/// to the background analysis path (asking the user via MCP elicitation when the
/// client supports it). 50 MiB chosen empirically — kernelcaches and DSCs are
/// typically larger than this and benefit from background analysis; smaller
/// binaries usually finish auto-analysis well within the foreground timeout.
pub(crate) const OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES: u64 = 50 * 1024 * 1024;
/// Bound the MCP elicitation prompt separately from IDA work. If the client
/// leaves the prompt unanswered, default to background analysis.
pub(crate) const OPEN_IDB_ELICITATION_TIMEOUT_SECS: u64 = 30;
pub(crate) const OPEN_IDB_REQUEST_STATE_TTL_SECS: u64 = 10 * 60;
/// Give foreground operations a short window to observe cancellation and clean
/// up owned resources before the MCP timeout/cancel response is returned.
pub(crate) const FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS: u64 = 6;

pub(crate) fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|err| {
        warn!(error = %err, "failed to pretty-print JSON response");
        value.to_string()
    })
}

/// Success result for a tool that declares an `outputSchema`.
///
/// A tool with an `outputSchema` must answer with `structuredContent` that
/// conforms to it (MCP 2025-06-18, "Tool Result"). This attaches that payload
/// *next to* the text block rather than in place of it: `text` stays whatever
/// the tool renders — pretty-printed JSON for listings, the raw listing for
/// disassembly and pseudocode — so declaring a schema costs a client that only
/// reads `content` nothing, while a client that reads `structuredContent` gets a
/// typed value.
///
/// Contrast with rmcp's `Json<T>` wrapper, which routes through
/// `CallToolResult::structured` and overwrites `content` with the compact
/// serialization of the same value. That would turn `decompile` from a C listing
/// into a one-line escaped JSON string.
pub(crate) fn structured_result(text: String, structured: Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![Content::text(text)]);
    result.structured_content = Some(structured);
    result
}

/// [`structured_result`] for the common case where the text block is the
/// pretty-printed form of the structured payload.
pub(crate) fn structured_json(value: Value) -> CallToolResult {
    structured_result(pretty_json(&value), value)
}

/// Failure result for a mutation whose worker answer is a status code.
///
/// Four tools ask IDA to change the database and get an `int` back rather than
/// a `Result`: `declare_stack`, `delete_stack`, `apply_types` and
/// `declare_type`. Reporting a non-zero code inside an `isError: false`
/// envelope would make every one of them indistinguishable from success to a
/// client that reads `isError` — which the MCP spec says is the field to read.
/// This flips `isError` while keeping the payload the tool's `outputSchema`
/// describes, so `code`, `offset` and `name` survive.
///
/// `message` must not interpolate database-supplied text. The supervisor
/// classifies a child's failure by substring (`worker channel closed`,
/// `timed out after`, `cancelled`), so a symbol name carrying one of those
/// phrases would masquerade as a lifecycle error; see
/// `crate::ida::remote::result_error`. Every caller below builds its message
/// from the tool name and numbers only.
pub(crate) fn structured_failure<T: serde::Serialize>(
    value: &T,
    tool: &str,
    message: String,
) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(detail) => ToolError::IdaErrorDetail {
            message,
            detail: Box::new(detail),
        }
        .to_tool_result(),
        Err(error) => {
            warn!(tool, error = %error, "failed to serialize tool failure payload");
            CallToolResult::error(vec![Content::text(message)])
        }
    }
}

/// Hard ceiling on how many hits one `search` / `find_bytes` pattern scans for.
///
/// The worker walks the database until it has this many, so it bounds the work
/// a single call can ask for. A page that runs into it is reported with
/// `total_is_lower_bound: true` rather than as a complete answer.
pub(crate) const BOUNDED_SCAN_CEILING: usize = 20000;

/// One page cut out of a bounded scan, with the truth about what it saw.
pub(crate) struct BoundedPage {
    matches: Vec<Value>,
    /// Hits the scan found. Equal to the real total only when
    /// `total_is_lower_bound` is false.
    total: usize,
    /// True when the scan stopped at its ceiling rather than at the end of the
    /// database, so more hits may exist beyond `total`.
    total_is_lower_bound: bool,
    next_offset: Option<usize>,
}

/// How far one `search` / `find_bytes` pattern scan is allowed to run.
///
/// One hit past the end of the requested page, so [`paginate_bounded_matches`]
/// can tell "the page is full and that is all there is" from "the page is full
/// and there is more". `_worker_max_results` (worker mode only) replaces the
/// whole calculation, because it exists to let the supervisor ask a child for
/// an exact number of hits.
pub(crate) fn bounded_scan_ceiling(
    offset: usize,
    limit: usize,
    worker_max_results: Option<usize>,
) -> usize {
    worker_max_results.unwrap_or_else(|| {
        offset
            .saturating_add(limit)
            .saturating_add(1)
            .min(BOUNDED_SCAN_CEILING)
    })
}

/// Turn a bounded scan into an honest page.
///
/// Reporting the scan's own length as `total` while capping the scan at
/// `offset + limit` is the trap here: `total` then comes back *equal to `limit`*
/// for any pattern with more hits than that, and `next_offset` — computed as
/// `offset + limit < total` — is arithmetically unreachable, so the answer reads
/// as "exactly `limit` matches and no further pages", a believable number and a
/// wrong one. Measured on a stock `/bin/cat` searching for `lib`, that shape
/// gives `total: 1` for `limit: 1`, `total: 5` for `limit: 5`, `total: 127` for
/// `limit: 2000`, with a null `next_offset` in all three.
///
/// So `total` is what the scan actually found, `total_is_lower_bound` says
/// whether it stopped early, and `next_offset` advances.
pub(crate) fn paginate_bounded_matches(
    matches: Vec<Value>,
    offset: usize,
    limit: usize,
    ceiling: usize,
) -> BoundedPage {
    let total = matches.len();
    let page = matches
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let consumed = offset.saturating_add(page.len());
    BoundedPage {
        matches: page,
        total,
        total_is_lower_bound: total >= ceiling,
        // Only claim another page when a hit was actually seen past this one.
        // At the ceiling there is nothing left to advance into, and
        // `total_is_lower_bound` is what says the answer is incomplete.
        next_offset: (total > consumed).then_some(consumed),
    }
}

/// Did a `declare_type` / `apply_types` payload report a failure?
///
/// Both tools answer with a `serde_json::Value` because both have two arms, and
/// the arms report failure differently: a non-zero IDA status `code`, an
/// `applied: false`, or (for `declare_type(multi=true)`, which parses a whole
/// header) a non-zero count of declarations that did not parse.
///
/// Returns the reason phrase for [`structured_failure`], built from numbers
/// only — never from a name the database supplied.
pub(crate) fn type_mutation_failure(payload: &Value) -> Option<String> {
    if let Some(code) = payload.get("code").and_then(Value::as_i64)
        && code != 0
    {
        return Some(format!("IDA returned code {code}"));
    }
    if payload.get("applied") == Some(&Value::Bool(false)) {
        return Some("IDA rejected the type".to_string());
    }
    if let Some(errors) = payload.get("errors").and_then(Value::as_i64)
        && errors != 0
    {
        return Some(format!("{errors} declaration(s) did not parse"));
    }
    None
}

/// [`structured_json`] for a value that is still a worker response type.
///
/// The worker types are plain data (strings, integers, bools, `Vec`, `Option`),
/// so `to_value` cannot fail for any of them; the error arm exists because the
/// alternative — emitting text with no `structuredContent` — would violate the
/// schema this tool advertises.
pub(crate) fn structured_value<T: serde::Serialize>(value: &T, tool: &str) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(json) => structured_json(json),
        Err(error) => {
            warn!(tool, error = %error, "failed to serialize tool response");
            CallToolResult::error(vec![Content::text(format!(
                "{tool} produced a response that could not be serialized: {error}"
            ))])
        }
    }
}

/// [`structured_value`] plus the mandatory `analysis_coverage` block.
///
/// The block is spliced into the serialized payload rather than carried by the
/// worker types, which know nothing about MCP. Splicing keeps the boundary
/// where it already is, at the cost of a shape the compiler cannot check — so
/// `every_coverage_schema_declares_the_key` in this module's tests asserts that
/// every schema declaring `analysis_coverage` gets it as a *required* property,
/// and `coverage_is_spliced_into_object_payloads` covers the splice itself.
pub(crate) fn structured_with_coverage<T: serde::Serialize>(
    value: &T,
    coverage: &responses::AnalysisCoverage,
    tool: &str,
) -> CallToolResult {
    match serde_json::to_value(value) {
        Ok(mut json) => {
            attach_analysis_coverage(&mut json, coverage, tool);
            structured_json(json)
        }
        Err(error) => {
            warn!(tool, error = %error, "failed to serialize tool response");
            CallToolResult::error(vec![Content::text(format!(
                "{tool} produced a response that could not be serialized: {error}"
            ))])
        }
    }
}

/// Splice `analysis_coverage` into an object payload.
///
/// A non-object payload is a bug in the caller — the whole point of the four
/// reshaped tools and of [`responses::ImportListOutput`] is that no tool that
/// owes a coverage block answers with a bare array — so this warns loudly and
/// leaves the payload alone rather than inventing a wrapper the schema does
/// not describe.
pub(crate) fn attach_analysis_coverage(
    value: &mut Value,
    coverage: &responses::AnalysisCoverage,
    tool: &str,
) {
    match value {
        Value::Object(map) => {
            map.insert(
                responses::ANALYSIS_COVERAGE_KEY.to_string(),
                coverage.to_json(),
            );
        }
        other => warn!(
            tool,
            kind = ?std::mem::discriminant(other),
            "analysis_coverage not attached: payload is not a JSON object"
        ),
    }
}

/// The snapshots are boxed because this rides in the `Err` arm of every
/// foreground tool call. `OperationSnapshot` is five `String`s and three
/// counters, so inlining it made the whole `Result` 160 bytes wide on the
/// success path too — paid by every call, for a payload only the two failure
/// arms ever read.
pub(crate) enum ForegroundOperationError {
    Tool(ToolError),
    TimedOut {
        timeout_secs: u64,
        snapshot: Box<OperationSnapshot>,
    },
    Cancelled {
        snapshot: Box<OperationSnapshot>,
    },
}

pub(crate) enum OpenIdbBackgroundDecision {
    Ready(bool),
    InputRequired(InputRequiredResult),
}

/// Which side of the xref relation the `xrefs_to`/`xrefs_from` tools query.
#[derive(Clone, Copy)]
pub(crate) enum XrefDirection {
    To,
    From,
}

impl XrefDirection {
    /// Name of the tool this direction serves, for diagnostics.
    fn tool_name(self) -> &'static str {
        match self {
            Self::To => "xrefs_to",
            Self::From => "xrefs_from",
        }
    }
}

impl IdaMcpServer {
    /// Sample the `analysis_coverage` block for the open database.
    ///
    /// Call this *before* the read it describes, never after. Completeness only
    /// moves forwards until an edit re-dirties the database, so a `complete`
    /// reading taken first still holds when the read finishes, while a
    /// `partial` reading taken first can only be pessimistic. Sampling
    /// afterwards inverts that: analysis settling mid-read would produce a
    /// `complete` badge on a payload that was half read from a partial
    /// database, which is the exact failure this block exists to prevent.
    ///
    /// One extra worker round trip per call. The handler behind it is two
    /// `db.meta()` reads, so the cost is the channel hop, not the work.
    async fn analysis_coverage(&self) -> responses::AnalysisCoverage {
        match self.worker.analysis_status().await {
            Ok(status) => responses::AnalysisCoverage::from_ida(&status),
            Err(error) => responses::AnalysisCoverage::unknown(&error.to_string()),
        }
    }

    pub fn new(worker: Arc<IdaWorker>, mode: ServerMode) -> Self {
        Self::with_filter(worker, mode, Arc::new(ToolPolicy::unrestricted()))
    }

    pub fn with_filter(worker: Arc<IdaWorker>, mode: ServerMode, filter: Arc<ToolPolicy>) -> Self {
        Self::with_filter_and_state(worker, mode, filter, ServerRuntimeState::new())
    }

    pub fn with_filter_and_state(
        worker: Arc<IdaWorker>,
        mode: ServerMode,
        filter: Arc<ToolPolicy>,
        state: ServerRuntimeState,
    ) -> Self {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_task_owner = task::TaskOwner::Session(Arc::from(session_id.as_str()));
        // debug!: sessionless MCP 2026 HTTP constructs a handler per request,
        // so this is per-request noise there, not a once-per-server event.
        debug!(
            session_id = %session_id,
            tool_filter_active = filter.is_active(),
            // Counted through the policy rather than tracked beside it, so
            // the number cannot disagree with what a client is served.
            enabled_tools = filter.advertise(catalog::native_tools()).len(),
            "Creating IDA MCP server handler"
        );
        let call_router = Self::tool_router();
        Self {
            worker,
            tool_mux: ToolMux::new(call_router),
            mode,
            task_registry: state.task_registry,
            operation_registry: state.operation_registry,
            operation_nonce: state.operation_nonce,
            runtime_lifetime: state.runtime_lifetime,
            session_lifetime: Arc::new(SessionLifetime::new()),
            request_state_codec: state.request_state_codec,
            session_id,
            session_task_owner,
            stateless_http: state.stateless_http,
            filter,
        }
    }

    /// Parent lifetime for background tasks spawned while serving `meta`'s
    /// request. Only HTTP uses metadata completeness to select rmcp's
    /// per-request sessionless route. Stdio always has one connection-scoped
    /// handler, even when an individual request carries the full key set.
    fn background_lifetime(&self, meta: &rmcp::model::RequestMetaObject) -> &SessionLifetime {
        if self.is_sessionless_http_request(meta) {
            &self.runtime_lifetime
        } else {
            &self.session_lifetime
        }
    }

    fn is_sessionless_http_request(&self, meta: &rmcp::model::RequestMetaObject) -> bool {
        // Under `--stateless` every HTTP request is per-handler regardless of
        // protocol version, so legacy requests must also use the runtime
        // owner and lifetime (see `ServerRuntimeState::stateless_http`).
        matches!(self.mode, ServerMode::Http)
            && (self.stateless_http || is_sessionless_request_meta(meta))
    }

    pub fn filter(&self) -> &Arc<ToolPolicy> {
        &self.filter
    }

    pub fn task_registry(&self) -> &task::TaskRegistry {
        &self.task_registry
    }

    fn close_hint(&self) -> &'static str {
        close_hint_for(self.mode)
    }

    fn http_close_grant(&self) -> Option<Result<CloseTokenGrant, String>> {
        if matches!(self.mode, ServerMode::Http) {
            Some(self.worker.issue_close_token_for_session(&self.session_id))
        } else {
            None
        }
    }

    fn apply_close_metadata(
        &self,
        map: &mut serde_json::Map<String, Value>,
        grant: Option<Result<CloseTokenGrant, String>>,
    ) {
        apply_close_metadata(map, grant, self.close_hint());
    }

    fn instructions(&self) -> String {
        format!(
            "IDA Pro headless analysis server for reverse engineering binaries. \
                 \n\nWorkflow: \
                 \n1. open_idb: Open a .i64/.idb file or a raw binary (Mach-O/ELF/PE). Large DBs may take 30+ seconds. \
                 \n   load_debug_info: Optional for existing .i64 to load DWARF/dSYM \
                 \n2. tool_catalog: Discover tools for your task (e.g., 'find callers', 'decompile') \
                 \n3. tool_help: Get full docs for a specific tool \
                 \n4. Use the discovered tools to analyze the binary \
                 \n5. close_idb: Optionally close when done \
                 \n\nNote: tools/list exposes the full tool set by default; use tool_catalog/tool_help to discover usage. \
                 \n{close_hint} \
                 \n\nTool Categories: \
                 \n- core: open/close/discover (open_idb, close_idb, tool_catalog, tool_help, recent_operations, idb_meta) \
                 \n- functions: list, resolve, lookup functions \
                 \n- disassembly: disasm at addresses \
                 \n- decompile: Hex-Rays pseudocode \
                 \n- xrefs: cross-reference analysis \
                 \n- control_flow: CFG, callgraph, paths \
                 \n- memory: read bytes, strings, values \
                 \n- search: find patterns, strings \
                 \n- metadata: segments, imports, exports, Lumina lookup \
                 \n- types: declare_type, apply_types (addr/stack), infer_types, local_types, stack_frame, declare_stack, delete_stack, structs (list/info/read) \
                \n- editing: comments/rename/patch/patch_asm/Lumina apply \
                 \n- scripting: run_script (execute IDAPython code) \
                 \n\nTip: Use tool_catalog(query='what you want to do') to find the right tool. \
                 \nTip: If xrefs/decompile look incomplete, call analysis_status to check auto-analysis. \
                 \nTip: After a timeout or cancellation, call recent_operations to inspect the last recorded foreground phase. \
                 \nTip: After dsc_add_dylib or dsc_add_region, call analysis_status; if auto_is_ok=false, run analyze_funcs before xrefs/decompile.",
            close_hint = self.close_hint()
        )
    }

    fn validate_path(path: &str) -> bool {
        let path = path.trim();
        let expanded = if let Some(stripped) = path.strip_prefix("~/") {
            if let Some(home) = std::env::var_os("HOME") {
                std::path::PathBuf::from(home).join(stripped)
            } else {
                return false;
            }
        } else {
            std::path::PathBuf::from(path)
        };
        let p = expanded.as_path();
        // Check: exists, is file, no path traversal
        // IDA can open many formats: .i64, .idb, ELF, Mach-O, PE, raw binaries, etc.
        p.exists() && p.is_file() && !path.contains("..")
    }

    fn parse_address(s: &str) -> Result<u64, ToolError> {
        crate::address::parse_address(s)
    }

    fn value_to_strings(value: &Value) -> Result<Vec<String>, ToolError> {
        address::value_to_strings(value)
    }

    /// Default page size for xref listings when the caller omits `limit`.
    const DEFAULT_XREFS_LIMIT: usize = 1000;
    /// Hard cap on a single xref page, mirroring other paginated tools.
    const MAX_XREFS_LIMIT: usize = 10000;

    // -----------------------------------------------------------------------
    // Composite tool ceilings
    // -----------------------------------------------------------------------
    //
    // A composite tool answers in one shot, so it cannot lean on a cursor to
    // stay cheap: every enumeration it performs needs a hard ceiling written
    // down here, advertised in the tool description, and echoed back in the
    // response's `limits` block. Without one, `survey_binary` on a 200k-symbol
    // firmware image would sit in a full-database walk until the transport
    // timeout kills it, which is exactly the failure a one-shot tool is
    // supposed to prevent.

    /// Ceiling on functions `survey_binary` lists and profiles.
    const MAX_SURVEY_FUNCTIONS: usize = 10_000;
    /// Ceiling on strings `survey_binary` lists and ranks.
    const MAX_SURVEY_STRINGS: usize = 5_000;
    /// Ceiling on imports `survey_binary` categorizes.
    const MAX_SURVEY_IMPORTS: usize = 10_000;
    /// Ceiling on exported/public names `survey_binary` counts.
    const MAX_SURVEY_EXPORTS: usize = 10_000;
    /// Default length of each `interesting_*` list.
    const DEFAULT_SURVEY_HIGHLIGHTS: usize = 15;
    /// Ceiling on the length of each `interesting_*` list.
    const MAX_SURVEY_HIGHLIGHTS: usize = 200;

    /// Ceiling on targets one `analyze_function` / `analyze_component` call
    /// may cover. Each `analyze_function` target costs up to six worker
    /// round trips, one of them a decompilation.
    const MAX_ANALYZE_TARGETS: usize = 32;
    /// Default instruction count for an `analyze_function` listing.
    const DEFAULT_ANALYZE_INSTRUCTIONS: usize = 400;
    /// Ceiling on instructions per `analyze_function` listing.
    const MAX_ANALYZE_INSTRUCTIONS: usize = 5_000;
    /// Default and ceiling for `callers`/`callees` in `analyze_function`.
    const DEFAULT_ANALYZE_RELATIVES: usize = 100;
    const MAX_ANALYZE_RELATIVES: usize = 1_000;
    /// Default and ceiling for `basic_blocks` in `analyze_function`.
    const DEFAULT_ANALYZE_BLOCKS: usize = 200;
    const MAX_ANALYZE_BLOCKS: usize = 2_000;
    /// Ceiling on the string index scan behind `referenced_strings`.
    const MAX_ANALYZE_STRINGS: usize = 5_000;
    /// Ceiling on recorded references per string in that index. A string
    /// referenced more often than this may be missing from a function's
    /// `referenced_strings` even though the reference exists.
    const ANALYZE_STRING_XREF_CAP: usize = 256;
    /// Strings listed on each `analyze_component` function summary.
    const MAX_COMPONENT_STRINGS: usize = 5;
    /// `xrefs_from` page size used to discover data refs at block starts.
    const MAX_COMPONENT_DATA_XREFS: usize = 256;

    /// Hard cap on nodes one `trace_data_flow` walk may visit.
    const TRACE_MAX_NODES: usize = 200;
    /// Hard cap on edges one `trace_data_flow` walk may record.
    const TRACE_MAX_EDGES: usize = 500;
    /// Per-node xref page size. One hop, not the whole function.
    const TRACE_XREFS_PER_NODE: usize = 32;
    /// Default / ceiling for `func_profile` list caps.
    const DEFAULT_PROFILE_ITEMS: usize = 20;
    const MAX_PROFILE_ITEMS: usize = 200;

    /// Parse and clamp the pagination inputs shared by `xrefs_to`/`xrefs_from`.
    ///
    /// Returns `(offset, limit, timeout_secs)`. The limit is clamped to
    /// `1..=MAX_XREFS_LIMIT`: the upper bound stops a high-frequency target from
    /// forcing an unbounded enumeration, and the lower bound of 1 guarantees a
    /// paginating caller always makes forward progress (a `limit` of 0 would
    /// return an empty-but-truncated page whose `next_offset` never advances).
    ///
    /// The clamping itself is `vibrev_kit::page::bounds`, so that argument holds
    /// wherever a page is cut rather than only here.
    fn parse_xrefs_paging(req: &XrefsRequest) -> Result<(usize, usize, Option<u64>), ToolError> {
        let (offset, limit) = page_bounds(
            req.offset,
            req.limit,
            Self::DEFAULT_XREFS_LIMIT,
            Self::MAX_XREFS_LIMIT,
        )?;
        let timeout_secs = parse_optional_unsigned::<u64>(req.timeout_secs, "timeout_secs")?;
        Ok((offset, limit, timeout_secs))
    }

    /// Wrap a per-address xref result for the multi-address response, injecting
    /// the queried address into the serialized listing.
    fn xrefs_entry(addr: u64, result: crate::ida::types::XRefListResult) -> Value {
        let mut entry = serde_json::to_value(&result).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut entry {
            map.insert("address".to_string(), json!(format!("{:#x}", addr)));
        }
        entry
    }

    /// Fetch one paginated xref listing in the given direction.
    async fn xrefs_for(
        &self,
        addr: u64,
        query: XrefQuery,
        timeout_secs: Option<u64>,
        direction: XrefDirection,
    ) -> Result<crate::ida::types::XRefListResult, ToolError> {
        match direction {
            XrefDirection::To => self.worker.xrefs_to(addr, query, timeout_secs).await,
            XrefDirection::From => self.worker.xrefs_from(addr, query, timeout_secs).await,
        }
    }

    /// Shared body of the `xrefs_to`/`xrefs_from` tools: parse pagination,
    /// resolve addresses, and assemble the single- or multi-address response.
    async fn xrefs_lookup(
        &self,
        req: XrefsRequest,
        direction: XrefDirection,
    ) -> Result<CallToolResult, McpError> {
        let (offset, limit, timeout_secs) = match Self::parse_xrefs_paging(&req) {
            Ok(paging) => paging,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let query = XrefQuery {
            offset,
            limit,
            kind: req.kind.unwrap_or_default(),
            dedup: req.dedup.unwrap_or(false),
            include_function: req.include_function.unwrap_or(false),
        };
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let coverage = self.analysis_coverage().await;
        if addrs.len() == 1 {
            match self
                .xrefs_for(addrs[0], query.clone(), timeout_secs, direction)
                .await
            {
                Ok(result) => Ok(structured_with_coverage(
                    &result,
                    &coverage,
                    direction.tool_name(),
                )),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self
                    .xrefs_for(addr, query.clone(), timeout_secs, direction)
                    .await
                {
                    Ok(result) => results.push(Self::xrefs_entry(addr, result)),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_with_coverage(
                &json!({ "results": results }),
                &coverage,
                direction.tool_name(),
            ))
        }
    }

    fn new_operation_id(&self) -> String {
        next_operation_id(self.operation_nonce.as_ref())
    }

    async fn finish_cancelled_foreground<T, Fut>(
        tool_name: &'static str,
        operation_fut: Pin<&mut Fut>,
    ) where
        Fut: std::future::Future<Output = Result<T, ToolError>>,
    {
        let cleanup = tokio::time::timeout(
            Duration::from_secs(FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS),
            operation_fut,
        )
        .await;
        if cleanup.is_err() {
            warn!(
                tool_name,
                timeout_secs = FOREGROUND_CANCEL_CLEANUP_TIMEOUT_SECS,
                "foreground operation did not finish cancellation cleanup before response"
            );
        }
    }

    async fn run_foreground_operation<T, F, Fut>(
        &self,
        ctx: &RequestContext<RoleServer>,
        tool_name: &'static str,
        target_summary: String,
        timeout_secs: Option<u64>,
        default_timeout_secs: u64,
        run: F,
    ) -> Result<T, ForegroundOperationError>
    where
        F: FnOnce(ProgressSender, tokio_util::sync::CancellationToken) -> Fut,
        Fut: std::future::Future<Output = Result<T, ToolError>>,
    {
        enum Outcome<T> {
            Finished(Result<T, ToolError>),
            TimedOut(u64),
            Cancelled,
        }

        let op_id = self.new_operation_id();
        self.operation_registry
            .start(op_id.clone(), tool_name, target_summary);

        let (progress_tx, mut progress_rx): (ProgressSender, ProgressReceiver) =
            tokio::sync::mpsc::unbounded_channel();
        // No `notifications/progress` are emitted: on stdio they race with the
        // response when fast tools coalesce into a single Node stdin `data`
        // event, dropping the Claude Code transport with "unknown progress
        // token". Phases remain observable via `recent_operations`.
        let drain_task = tokio::spawn({
            let registry = self.operation_registry.clone();
            let op_id = op_id.clone();
            async move {
                while let Some(update) = progress_rx.recv().await {
                    registry.record_progress(&op_id, update.phase, update.message);
                }
            }
        });
        let worker_cancel = tokio_util::sync::CancellationToken::new();
        let timeout = timeout_secs
            .unwrap_or(default_timeout_secs)
            .min(MAX_TIMEOUT_SECS);
        let client_cancel = ctx.ct.clone();

        let operation_fut = run(progress_tx, worker_cancel.clone());
        tokio::pin!(operation_fut);

        let outcome = tokio::select! {
            biased;
            result = &mut operation_fut => Outcome::Finished(result),
            _ = client_cancel.cancelled() => {
                worker_cancel.cancel();
                Outcome::Cancelled
            }
            _ = tokio::time::sleep(Duration::from_secs(timeout)) => {
                worker_cancel.cancel();
                Outcome::TimedOut(timeout)
            }
        };

        match outcome {
            Outcome::Finished(result) => {
                let _ = drain_task.await;
                match result {
                    Ok(value) => {
                        let _ = self.operation_registry.finish_completed(
                            &op_id,
                            format!("{tool_name} completed successfully"),
                        );
                        Ok(value)
                    }
                    Err(ToolError::Cancelled(_)) => {
                        let snapshot = self
                            .operation_registry
                            .finish_cancelled(&op_id, format!("{tool_name} cancelled"))
                            .or_else(|| self.operation_registry.snapshot(&op_id))
                            .unwrap_or_else(|| {
                                Self::fallback_operation_snapshot(
                                    &op_id,
                                    tool_name,
                                    "cancelled",
                                    operation::OperationStatus::Cancelled,
                                    format!("{tool_name} cancelled"),
                                )
                            });
                        Err(ForegroundOperationError::Cancelled {
                            snapshot: Box::new(snapshot),
                        })
                    }
                    Err(error) => {
                        let _ = self
                            .operation_registry
                            .finish_failed(&op_id, format!("{tool_name} failed: {error}"));
                        Err(ForegroundOperationError::Tool(error))
                    }
                }
            }
            Outcome::TimedOut(timeout_secs) => {
                Self::finish_cancelled_foreground(tool_name, operation_fut.as_mut()).await;
                drain_task.abort();
                let _ = drain_task.await;
                let snapshot = self
                    .operation_registry
                    .finish_timed_out(
                        &op_id,
                        format!("{tool_name} timed out after {timeout_secs}s"),
                    )
                    .or_else(|| self.operation_registry.snapshot(&op_id))
                    .unwrap_or_else(|| {
                        Self::fallback_operation_snapshot(
                            &op_id,
                            tool_name,
                            "timed_out",
                            operation::OperationStatus::TimedOut,
                            format!("{tool_name} timed out after {timeout_secs}s"),
                        )
                    });
                Err(ForegroundOperationError::TimedOut {
                    timeout_secs,
                    snapshot: Box::new(snapshot),
                })
            }
            Outcome::Cancelled => {
                Self::finish_cancelled_foreground(tool_name, operation_fut.as_mut()).await;
                drain_task.abort();
                let _ = drain_task.await;
                let snapshot = self
                    .operation_registry
                    .finish_cancelled(&op_id, format!("{tool_name} cancelled by client"))
                    .or_else(|| self.operation_registry.snapshot(&op_id))
                    .unwrap_or_else(|| {
                        Self::fallback_operation_snapshot(
                            &op_id,
                            tool_name,
                            "cancelled",
                            operation::OperationStatus::Cancelled,
                            format!("{tool_name} cancelled by client"),
                        )
                    });
                Err(ForegroundOperationError::Cancelled {
                    snapshot: Box::new(snapshot),
                })
            }
        }
    }

    fn operation_timeout_message(
        tool_name: &str,
        timeout_secs: u64,
        snapshot: &OperationSnapshot,
        detail: Option<String>,
    ) -> String {
        let mut message = format!(
            "{tool_name} timed out after {timeout_secs} seconds.\n\
             Last known phase: {}.\n\
             Operation id: {}.\n\
             Elapsed: {} ms.\n\
             Check recent_operations for the recorded event trail.",
            snapshot.phase, snapshot.op_id, snapshot.elapsed_ms
        );
        if let Some(detail) = detail {
            message.push_str("\n\n");
            message.push_str(&detail);
        }
        message
    }

    fn operation_cancelled_message(tool_name: &str, snapshot: &OperationSnapshot) -> String {
        format!(
            "{tool_name} was cancelled by the client.\n\
             Last known phase: {}.\n\
             Operation id: {}.\n\
             Elapsed: {} ms.\n\
             Check recent_operations for the recorded event trail.",
            snapshot.phase, snapshot.op_id, snapshot.elapsed_ms
        )
    }

    fn fallback_operation_snapshot(
        op_id: &str,
        tool_name: &str,
        phase: &str,
        status: operation::OperationStatus,
        message: String,
    ) -> OperationSnapshot {
        OperationSnapshot {
            op_id: op_id.to_string(),
            tool: tool_name.to_string(),
            target_summary: "unknown".to_string(),
            phase: phase.to_string(),
            status,
            message,
            started_at_ms: 0,
            last_update_ms: 0,
            elapsed_ms: 0,
        }
    }

    fn start_dsc_background(
        &self,
        owner: &task::TaskOwner,
        dedup_key: String,
        initial_message: &str,
        ctx: DscBackgroundCtx,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        let task_id = match self.task_registry.create_keyed(
            owner,
            "dsc",
            &dedup_key,
            initial_message,
        ) {
            Ok(id) => id,
            Err(task::TaskCreateError::AlreadyRunning(existing_id)) => {
                return Ok(structured_json(json!({
                    "status": "already_running",
                    "task_id": existing_id,
                    "message": "A DSC loading task for this path is already in progress. Poll task_status(task_id) for progress.",
                })));
            }
            Err(error) => return Ok(task_create_error_to_tool_error(error).to_tool_result()),
        };

        let backend = match &ctx.open {
            DscBackgroundOpen::DirectRawDsc { .. } => "dscu",
            DscBackgroundOpen::LegacyIdat { .. } => "idat",
        };
        info!(
            module = %ctx.module,
            backend,
            "Spawning background DSC loading"
        );

        let registry = self.task_registry.clone();
        let worker = self.worker.clone();
        let mode = self.mode;
        let tid = task_id.clone();
        let task_cancel_token = cancel_token.clone();
        tokio::spawn(async move {
            Self::run_dsc_background(tid, registry, worker, mode, ctx, task_cancel_token).await;
        });
        self.task_registry.set_cancel_token(&task_id, cancel_token);

        Ok(structured_json(json!({
            "status": "started",
            "task_id": task_id,
            "message": "DSC loading started in background. Poll task_status(task_id) for progress.",
        })))
    }

    /// Open a DSC database synchronously, load the requested images, and return db_info.
    async fn open_dsc_direct(
        &self,
        open_path: &std::path::Path,
        file_type: Option<&str>,
        module: &str,
        frameworks: &[String],
    ) -> Result<CallToolResult, McpError> {
        info!(path = %open_path.display(), file_type, "Opening DSC directly through idalib");

        let open_path_str = open_path.display().to_string();
        // Bind the image loads below to the database this call opened. The IDA
        // worker serves every session, so another session's close_idb between
        // the open and a load would otherwise redirect the load — which
        // mutates the database — into whatever database is current.
        let open_result = self
            .worker
            .open_observed_with_generation(
                crate::ida::OpenSpec {
                    path: open_path_str,
                    file_type: file_type.map(str::to_string),
                    ..Default::default()
                },
                None,
                None,
                None,
            )
            .await;

        let (db_info, generation) = match open_result {
            Ok(opened) => (opened.info, Some(opened.generation)),
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut loaded_images = Vec::with_capacity(frameworks.len() + 1);
        let mut dsc_warning = None;
        match self
            .worker
            .dsc_load_image_for_generation(module, Some(600), generation)
            .await
        {
            Ok(image) => loaded_images.push(image),
            Err(ToolError::NotSupported(message)) if file_type.is_none() => {
                dsc_warning = Some(format!(
                    "Opened existing IDA database, but native DSC loading is unavailable: {message}"
                ));
            }
            Err(e) => return Ok(e.to_tool_result()),
        }
        if dsc_warning.is_none() {
            for framework in frameworks {
                match self
                    .worker
                    .dsc_load_image_for_generation(framework, Some(600), generation)
                    .await
                {
                    Ok(image) => loaded_images.push(image),
                    Err(e) => return Ok(e.to_tool_result()),
                }
            }
        }

        let analysis_status = match self.worker.analysis_status_for_generation(generation).await {
            Ok(status) => Some(status),
            Err(err) => {
                warn!(module = %module, error = %err, "failed to fetch analysis_status after open_dsc");
                None
            }
        };
        let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
        let next_step_hint = if dsc_warning.is_some() {
            "Existing .i64 opened, but native DSC loading was unavailable; inspect loaded modules before xrefs/decompile/list_functions."
        } else {
            "Proceed with xrefs/decompile/list_functions for the loaded DSC module."
        };
        let next_steps = dsc_analysis_next_steps(analysis_ready, next_step_hint);

        let close_token = self.http_close_grant();

        let mut value = match serde_json::to_value(&db_info) {
            Ok(v) => v,
            Err(_) => {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "{db_info:?}"
                ))]));
            }
        };
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if let Some(module_info) = loaded_images.first() {
                map.insert("module_info".to_string(), json!(module_info));
            }
            let dsc_backend = if dsc_warning.is_some() {
                "unavailable"
            } else {
                "dscu"
            };
            map.insert("dsc_backend".to_string(), json!(dsc_backend));
            map.insert("loaded_images".to_string(), json!(loaded_images));
            if let Some(warning) = dsc_warning {
                map.insert("dsc_warning".to_string(), json!(warning));
            }
            map.insert("analysis_status".to_string(), json!(analysis_status));
            map.insert("analysis_ready".to_string(), json!(analysis_ready));
            map.insert("next_steps".to_string(), json!(next_steps));
            if !matches!(self.mode, ServerMode::Worker) {
                self.apply_close_metadata(map, close_token);
            }
        }

        Ok(structured_json(value))
    }

    fn complete_background_tool_error(
        task_id: &str,
        registry: &task::TaskRegistry,
        error: &ToolError,
        cancel_token: &tokio_util::sync::CancellationToken,
        cancel_message: &str,
    ) -> task::TaskSettlement {
        registry.complete_with_cancel_token(
            task_id,
            call_tool_result_to_value(&error.to_tool_result()),
            cancel_token,
            cancel_message,
        )
    }

    async fn finish_dsc_tool_error_after_open(
        task_id: &str,
        registry: &task::TaskRegistry,
        worker: &Arc<IdaWorker>,
        generation: DatabaseGeneration,
        error: ToolError,
        cancel_token: &tokio_util::sync::CancellationToken,
    ) {
        match worker.close_if_generation(generation).await {
            Ok(ConditionalCloseResult::Closed | ConditionalCloseResult::NotCurrent) => {
                Self::complete_background_tool_error(
                    task_id,
                    registry,
                    &error,
                    cancel_token,
                    "Cancelled after the failed DSC operation settled",
                );
            }
            Err(close_error) => {
                let message = format!(
                    "{error}; cleanup failed for database generation {}: {close_error}",
                    generation.0
                );
                warn!(error = %message, "background DSC failure cleanup did not settle safely");
                registry.fail_after_cleanup_error(task_id, &message);
            }
        }
    }

    async fn finish_dsc_cancellation_after_open(
        task_id: &str,
        registry: &task::TaskRegistry,
        worker: &Arc<IdaWorker>,
        generation: DatabaseGeneration,
    ) {
        match worker.close_if_generation(generation).await {
            Ok(ConditionalCloseResult::Closed) => {
                registry.finish_cancelled(
                    task_id,
                    "Cancelled after the active DSC operation settled and its database closed",
                );
            }
            Ok(ConditionalCloseResult::NotCurrent) => {
                registry.finish_cancelled(
                    task_id,
                    "Cancelled after the active DSC operation settled; its database generation was already replaced",
                );
            }
            Err(error) => {
                let message = format!(
                    "Cancellation cleanup failed for database generation {}: {error}",
                    generation.0
                );
                warn!(error = %error, "failed to close cancelled DSC database generation");
                registry.fail_after_cleanup_error(task_id, &message);
            }
        }
    }

    /// Background task: open a DSC through the selected backend, then load images.
    async fn run_dsc_background(
        task_id: String,
        registry: task::TaskRegistry,
        worker: Arc<IdaWorker>,
        mode: ServerMode,
        ctx: DscBackgroundCtx,
        cancel_token: tokio_util::sync::CancellationToken,
    ) {
        let DscBackgroundCtx {
            open,
            module,
            frameworks,
            owner_session_id,
        } = ctx;

        if cancel_token.is_cancelled() {
            registry.finish_cancelled(&task_id, "Cancelled by session shutdown");
            return;
        }

        let (open_path, idb_out, auto_analyse, load_images_with_dscu) = match open {
            DscBackgroundOpen::DirectRawDsc { open_path, idb_out } => {
                info!(
                    path = %open_path.display(),
                    idb_out = %idb_out.display(),
                    "Background: opening raw DSC through idalib"
                );
                registry.update_message(&task_id, "Opening DSC directly with idalib...");
                (open_path, Some(idb_out), false, true)
            }
            DscBackgroundOpen::LegacyIdat {
                idat,
                idat_args,
                script_path,
                log_path,
                out_i64,
            } => {
                let mut script_cleanup = TemporaryFileCleanup::new(script_path);

                // Phase 1: run idat subprocess
                info!("Background: running idat");
                registry.update_message(&task_id, "Running idat to create .i64...");

                let mut cmd = tokio::process::Command::new(&idat);
                cmd.args(&idat_args);
                // Remove env vars that cause license conflicts when our
                // process links idalib and also spawns idat.
                cmd.env_remove("IDADIR");
                cmd.env_remove("DYLD_LIBRARY_PATH");
                cmd.env("IDA_DYLD_CACHE_MODULE", &module);
                // idat's diagnostics go to stderr and the -L log file; stdout
                // is never read, and leaving it on an undrained pipe could
                // block idat once the buffer fills.
                cmd.stdout(std::process::Stdio::null());
                cmd.stderr(std::process::Stdio::piped());

                let (exit_code, stderr) = match cmd.spawn() {
                    Ok(mut child) => {
                        let mut stderr_pipe = child.stderr.take();
                        let mut stderr_buf = Vec::new();
                        let status = {
                            let wait = async {
                                if let Some(pipe) = stderr_pipe.as_mut() {
                                    use tokio::io::AsyncReadExt as _;
                                    let _ = pipe.read_to_end(&mut stderr_buf).await;
                                }
                                child.wait().await
                            };
                            tokio::pin!(wait);
                            tokio::select! {
                                status = &mut wait => Some(status),
                                () = cancel_token.cancelled() => None,
                            }
                        };
                        let Some(status) = status else {
                            // Kill idat and reap it before publishing the
                            // terminal state, so no IDA work survives a task
                            // that reports itself cancelled. A killed idat can
                            // leave partial database files that dsc_open_plan
                            // would reuse on the next call — remove them.
                            stop_idat_and_remove_partial_outputs(&mut child, &out_i64).await;
                            registry.finish_cancelled(
                                &task_id,
                                "Cancelled; the idat subprocess was killed and its partial output removed",
                            );
                            return;
                        };
                        let exit_code = match status {
                            Ok(status) => status.code().unwrap_or(-1),
                            Err(e) => {
                                stop_idat_and_remove_partial_outputs(&mut child, &out_i64).await;
                                registry.fail(&task_id, &format!("failed to wait for idat: {e}"));
                                return;
                            }
                        };
                        (exit_code, String::from_utf8_lossy(&stderr_buf).into_owned())
                    }
                    Err(e) => (-1, format!("Failed to spawn idat: {e}")),
                };

                if cancel_token.is_cancelled() {
                    registry
                        .finish_cancelled(&task_id, "Cancelled after the idat subprocess settled");
                    return;
                }

                // Clean up the temporary load script now; the guard still covers early returns above.
                script_cleanup.cleanup_now();

                if exit_code != 0 || !out_i64.exists() {
                    let log_tail = log_path
                        .as_ref()
                        .and_then(|p| std::fs::read_to_string(p).ok())
                        .map(|s| {
                            let lines: Vec<&str> = s.lines().collect();
                            let start = lines.len().saturating_sub(20);
                            lines[start..].join("\n")
                        });

                    let mut msg = format!("idat exited with code {exit_code}.\nstderr: {stderr}");
                    if let Some(tail) = log_tail {
                        msg.push_str(&format!("\nlog (last 20 lines):\n{tail}"));
                    }
                    remove_partial_idat_outputs(&out_i64);
                    warn!(exit_code, "idat failed");
                    Self::complete_background_tool_error(
                        &task_id,
                        &registry,
                        &ToolError::OpenFailed(msg),
                        &cancel_token,
                        "Cancelled after the idat subprocess settled",
                    );
                    return;
                }

                info!("idat completed, opening .i64");
                registry.update_message(&task_id, "Opening database with idalib...");
                (out_i64, None, true, false)
            }
        };

        // Phase 2: open the database with idalib.
        let open_path_str = open_path.display().to_string();
        let open_result = worker
            .open_observed_with_generation(
                crate::ida::OpenSpec {
                    path: open_path_str,
                    auto_analyse,
                    idb_out: idb_out.as_ref().map(|path| path.display().to_string()),
                    ..Default::default()
                },
                None,
                None,
                Some(cancel_token.clone()),
            )
            .await;

        let opened = match open_result {
            Ok(opened) => {
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        opened.generation,
                    )
                    .await;
                    return;
                }
                opened
            }
            Err(e) => {
                Self::complete_background_tool_error(
                    &task_id,
                    &registry,
                    &e,
                    &cancel_token,
                    "Cancelled after the DSC open operation settled",
                );
                return;
            }
        };
        let db_info = opened.info;
        let database_generation = opened.generation;

        let mut loaded_images = Vec::new();
        let mut analysis_status = None;
        let mut analysis_ready = None;
        let mut next_steps = None;
        if load_images_with_dscu {
            registry.update_message(&task_id, "Loading DSC module through ida_dscu...");
            let module_result = worker
                .dsc_load_image_for_generation(&module, Some(600), Some(database_generation))
                .await;
            if cancel_token.is_cancelled() {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
                return;
            }
            match module_result {
                Ok(image) => loaded_images.push(image),
                Err(e) => {
                    Self::finish_dsc_tool_error_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                        ToolError::IdaError(format!("Failed to load DSC module {module}: {e}")),
                        &cancel_token,
                    )
                    .await;
                    return;
                }
            }

            for framework in &frameworks {
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                    )
                    .await;
                    return;
                }
                registry.update_message(&task_id, &format!("Loading DSC framework {framework}..."));
                let framework_result = worker
                    .dsc_load_image_for_generation(framework, Some(600), Some(database_generation))
                    .await;
                if cancel_token.is_cancelled() {
                    Self::finish_dsc_cancellation_after_open(
                        &task_id,
                        &registry,
                        &worker,
                        database_generation,
                    )
                    .await;
                    return;
                }
                match framework_result {
                    Ok(image) => loaded_images.push(image),
                    Err(e) => {
                        Self::finish_dsc_tool_error_after_open(
                            &task_id,
                            &registry,
                            &worker,
                            database_generation,
                            ToolError::IdaError(format!(
                                "Failed to load DSC framework {framework}: {e}"
                            )),
                            &cancel_token,
                        )
                        .await;
                        return;
                    }
                }
            }

            let analysis_status_result = worker
                .analysis_status_for_generation(Some(database_generation))
                .await;
            if cancel_token.is_cancelled() {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
                return;
            }
            analysis_status = match analysis_status_result {
                Ok(status) => Some(status),
                Err(err) => {
                    warn!(module = %module, error = %err, "failed to fetch analysis_status after background open_dsc");
                    None
                }
            };
            analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
            next_steps = Some(dsc_analysis_next_steps(
                analysis_ready,
                "Proceed with xrefs/decompile/list_functions for the loaded DSC module.",
            ));
        }

        if cancel_token.is_cancelled() {
            Self::finish_dsc_cancellation_after_open(
                &task_id,
                &registry,
                &worker,
                database_generation,
            )
            .await;
            return;
        }

        let close_token = match (mode, owner_session_id.as_deref()) {
            (ServerMode::Http, Some(owner_session_id)) => {
                Some(worker.issue_close_token_for_session(owner_session_id))
            }
            _ => None,
        };

        let mut value = serde_json::to_value(&db_info)
            .unwrap_or_else(|_| json!({"info": format!("{db_info:?}")}));
        if let Value::Object(map) = &mut value {
            map.insert("module".to_string(), json!(module));
            if !frameworks.is_empty() {
                map.insert("frameworks_loaded".to_string(), json!(frameworks));
            }
            if load_images_with_dscu {
                if let Some(module_info) = loaded_images.first() {
                    map.insert("module_info".to_string(), json!(module_info));
                }
                map.insert("dsc_backend".to_string(), json!("dscu"));
                map.insert("loaded_images".to_string(), json!(loaded_images));
                map.insert("analysis_status".to_string(), json!(analysis_status));
                map.insert("analysis_ready".to_string(), json!(analysis_ready));
                map.insert("next_steps".to_string(), json!(next_steps));
            }
            apply_close_metadata(map, close_token, close_hint_for(mode));
        }

        match registry.complete_or_defer_cancellation(&task_id, value, &cancel_token) {
            task::TaskCompletionDecision::Completed => {
                info!("DSC background task completed");
            }
            task::TaskCompletionDecision::CancellationPending => {
                Self::finish_dsc_cancellation_after_open(
                    &task_id,
                    &registry,
                    &worker,
                    database_generation,
                )
                .await;
            }
            task::TaskCompletionDecision::Unchanged => {}
        }
    }
}

/// Short-circuit on a `Result<_, ToolError>` from within a `#[tool]` async fn,
/// surfacing the error to the client as an `is_error: true` CallToolResult
/// (matching the existing `Err(e) => Ok(e.to_tool_result())` pattern used by
/// the rest of the handlers).
macro_rules! try_param {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        }
    };
}

/// [`try_param`] for a worker call rather than an argument parse.
///
/// Same short-circuit, different name so a reader of a composite tool can tell
/// at a glance which failures are the caller's fault and which are the
/// database's.
macro_rules! try_worker {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(error) => return Ok(error.to_tool_result()),
        }
    };
}

/// One function's or string's centrality counts, as returned by the worker's
/// `survey_metrics` pass.
#[derive(Clone, Copy, Default)]
pub(crate) struct SurveyMetric {
    /// References of any kind to the address.
    xrefs: u64,
    /// Distinct functions that call this one; always 0 for a string.
    incoming_calls: u64,
    /// Distinct functions this one calls; always 0 for a string.
    outgoing_calls: u64,
}

/// Index one arm of the `survey_metrics` payload by address.
///
/// The payload is `{"functions": [{address, xrefs, incoming_calls,
/// outgoing_calls}, ...], "strings": [{address, xrefs}, ...]}` with addresses
/// hex-formatted. Entries whose address does not parse are dropped: a missing
/// metric degrades a ranking, a panic would lose the whole survey.
pub(crate) fn survey_metric_index(
    metrics: Option<&Value>,
    arm: &str,
) -> std::collections::HashMap<u64, SurveyMetric> {
    metrics
        .and_then(|value| value.get(arm))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    let address = entry.get("address").and_then(Value::as_str)?;
                    let address = IdaMcpServer::parse_address(address).ok()?;
                    Some((
                        address,
                        SurveyMetric {
                            xrefs: entry.get("xrefs").and_then(Value::as_u64).unwrap_or(0),
                            incoming_calls: entry
                                .get("incoming_calls")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                            outgoing_calls: entry
                                .get("outgoing_calls")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Default walk direction when the caller omitted `direction`.
pub(crate) fn trace_direction_or_default(direction: Option<TraceDirection>) -> TraceDirection {
    direction.unwrap_or(TraceDirection::Forward)
}

/// `trace_data_flow.max_depth`: default 5, never outside `1..=20`.
pub(crate) fn clamp_trace_max_depth(max_depth: Option<i64>) -> usize {
    max_depth.unwrap_or(5).clamp(1, 20) as usize
}

/// One xref as the `trace_data_flow` stepper sees it (parsed addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraceXrefHop {
    pub from: u64,
    pub to: u64,
    pub is_code: bool,
}

/// One edge the stepper wants to emit, still as integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraceHopEdge {
    pub from: u64,
    pub to: u64,
    pub is_code: bool,
}

/// Given the xrefs of `current`, emit new edges and the unvisited next hops.
///
/// Visited addresses are skipped from the next layer but still produce an
/// edge — the graph should show the connection even when BFS does not
/// re-enqueue the node.
pub(crate) fn trace_data_flow_step(
    current: u64,
    direction: TraceDirection,
    xrefs: &[TraceXrefHop],
    visited: &std::collections::HashSet<u64>,
) -> (Vec<TraceHopEdge>, Vec<u64>) {
    let mut edges = Vec::with_capacity(xrefs.len());
    let mut next = Vec::new();
    for xref in xrefs {
        let (from, to, neighbor) = match direction {
            TraceDirection::Forward => (current, xref.to, xref.to),
            TraceDirection::Backward => (xref.from, current, xref.from),
        };
        edges.push(TraceHopEdge {
            from,
            to,
            is_code: xref.is_code,
        });
        if !visited.contains(&neighbor) && !next.contains(&neighbor) {
            next.push(neighbor);
        }
    }
    (edges, next)
}

/// First `limit` distinct non-empty string values, in encounter order.
pub(crate) fn compact_component_strings<I, S>(values: I, limit: usize) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for value in values {
        let value = value.as_ref();
        if value.is_empty() || !seen.insert(value.to_string()) {
            continue;
        }
        out.push(value.to_string());
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Restrict a callee list to edges whose both ends sit in `component_starts`.
///
/// `component_starts` is request order and becomes `nodes`. Each callee is
/// `(caller_start, callee_start, callee_name)`.
pub(crate) fn component_internal_call_graph(
    component_starts: &[u64],
    callees: &[(u64, u64, &str)],
) -> responses::ComponentCallGraph {
    let member: std::collections::HashSet<u64> = component_starts.iter().copied().collect();
    let nodes = component_starts
        .iter()
        .map(|addr| format!("{addr:#x}"))
        .collect();
    let mut edges = Vec::new();
    for &(from, to, name) in callees {
        if member.contains(&from) && member.contains(&to) {
            edges.push(responses::ComponentCallEdge {
                from: format!("{from:#x}"),
                to: format!("{to:#x}"),
                name: name.to_string(),
            });
        }
    }
    responses::ComponentCallGraph { nodes, edges }
}

pub(crate) fn close_hint_for(mode: ServerMode) -> &'static str {
    match mode {
        ServerMode::Stdio => "Call close_idb when done to release locks for other sessions.",
        ServerMode::Http => {
            "In HTTP/SSE mode, keep the close_token returned by open_idb. Sessionless MCP 2026 and non-owning legacy contexts must pass it to close_idb; the owning legacy session can close directly. If the token is lost, close_idb(force=true) can recover the shared IDA context."
        }
        ServerMode::Worker => {
            "Child worker mode is managed by the parent router; close_idb is normally called by the parent."
        }
    }
}

/// Stop and reap an idat child before removing database artifacts that cannot
/// be trusted after cancellation or a wait failure.
pub(crate) async fn stop_idat_and_remove_partial_outputs(
    child: &mut tokio::process::Child,
    out_i64: &std::path::Path,
) {
    let _ = child.start_kill();
    let _ = child.wait().await;
    remove_partial_idat_outputs(out_i64);
}

/// Best-effort removal of what an incomplete idat run leaves behind: the packed
/// `.i64` (which `dsc_open_plan` would reuse as-is on the next `open_dsc`)
/// and the unpacked database components idat works in before packing.
pub(crate) fn remove_partial_idat_outputs(out_i64: &std::path::Path) {
    let mut paths = vec![out_i64.to_path_buf()];
    for ext in ["id0", "id1", "id2", "nam", "til"] {
        paths.push(out_i64.with_extension(ext));
    }
    for path in paths {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(path = %path.display(), "removed untrusted partial idat output");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to remove partial idat output");
            }
        }
    }
}

/// Insert close-ownership metadata onto a tool result, identical for foreground
/// `open_idb` and the DSC background task so clients see one shape via both
/// paths.
pub(crate) fn apply_close_metadata(
    map: &mut serde_json::Map<String, Value>,
    grant: Option<Result<CloseTokenGrant, String>>,
    close_hint: &str,
) {
    match grant {
        Some(Ok(grant)) => {
            map.insert("close_hint".to_string(), json!(close_hint));
            map.insert(
                "close_owner_session_id".to_string(),
                json!(grant.owner_session_id),
            );
            map.insert("close_token".to_string(), json!(grant.token));
            if grant.reused {
                map.insert("close_token_reused".to_string(), json!(true));
            }
        }
        Some(Err(owner_session_id)) => {
            map.insert(
                "close_hint".to_string(),
                json!(format!(
                    "The open database is currently owned by HTTP context {owner_session_id}. Provide its close_token to close_idb, or call close_idb(force=true) if that token was lost."
                )),
            );
            map.insert(
                "close_owner_session_id".to_string(),
                json!(owner_session_id),
            );
            map.insert(
                "close_recovery_hint".to_string(),
                json!(
                    "If the original close_token was lost, call close_idb(force=true) from a trusted client."
                ),
            );
        }
        None => {
            map.insert("close_hint".to_string(), json!(close_hint));
        }
    }
}

pub(crate) fn dsc_analysis_next_steps(
    analysis_ready: Option<bool>,
    ready_message: &'static str,
) -> Vec<String> {
    if analysis_ready == Some(true) {
        vec![ready_message.to_string()]
    } else {
        vec![
            "Call analysis_status to check auto-analysis progress.".to_string(),
            "If auto_is_ok is false, run analyze_funcs and wait for completion before xrefs/decompile."
                .to_string(),
        ]
    }
}

pub(crate) use crate::ida::handlers::hex_encode;

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use vibrev_kit::decorate::Decorator;

/// Every version this engine can speak, oldest first, with the modern
/// (sessionless) protocol last. Both faces publish this one list — the worker's
/// `ServerHandler` and the supervisor's — so a client negotiates against the
/// same answer whichever it reaches, and no face clips the sessionless 2026
/// lifecycle off the end.
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2024_11_05,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2026_07_28,
];

pub(crate) fn supported_protocol_versions() -> Cow<'static, [ProtocolVersion]> {
    Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
}

/// Translate a rejected admission into this engine's error taxonomy.
///
/// The kit knows *that* a task was refused and why in registry terms; only this
/// engine knows which of its own errors the client should read, which is why
/// this mapping stays here rather than in the kit.
pub(crate) fn task_create_error_to_tool_error(error: task::TaskCreateError) -> ToolError {
    match error {
        task::TaskCreateError::AlreadyRunning(_) => ToolError::Busy,
        task::TaskCreateError::ExistingTaskIdIsPrivate => ToolError::BackgroundTaskHandlePrivate,
        task::TaskCreateError::CapacityExceeded { max_entries } => {
            ToolError::BackgroundTaskRegistryFull { max: max_entries }
        }
    }
}

/// The two questions [`vibrev_kit::tasks::TaskHost`] cannot answer from the
/// protocol alone. Everything else about `tasks/get`, `tasks/update` and
/// `tasks/cancel` is the kit's.
///
/// Owner resolution is the interesting half, and it is why this is a trait impl
/// rather than a wrapper: it reads two fields of *this* handler — the transport
/// it runs on and whether that transport was started stateless — that no
/// decorator could see without being handed copies and kept in step.
impl task::TaskHost for IdaMcpServer {
    fn task_registry(&self) -> &task::TaskRegistry {
        &self.task_registry
    }

    /// Sessionless HTTP requests share one owner because MCP 2026 supplies no
    /// stable session identifier across requests. Stdio remains bound to its
    /// connection-scoped handler regardless of per-request metadata shape.
    fn task_owner(&self, meta: &rmcp::model::RequestMetaObject) -> task::TaskOwner {
        if self.is_sessionless_http_request(meta) {
            task::TaskOwner::Runtime
        } else {
            self.session_task_owner.clone()
        }
    }
}

include!("tools.rs");
include!("handler.rs");

#[cfg(test)]
mod tests;
