//! Headless IDA Pro MCP Server
//!
//! This library provides an MCP (Model Context Protocol) server for headless
//! IDA Pro access. It allows LLM agents to open IDA databases, list functions,
//! get disassembly, and decompile code.
//!
//! # Architecture
//!
//! IDA **must** run on the main thread. The architecture is:
//!
//! - **Main thread**: Runs the IDA worker loop (`ida::run_ida_loop`).
//!   All idalib operations happen here.
//!
//! - **Background thread**: Runs the tokio runtime with the async MCP server.
//!   Communicates with the main thread via channels.
//!
//! - **IdaWorker**: Handle for sending requests to the main thread.
//!
//! - **IdaMcpServer**: The MCP server that exposes tools for IDA operations.
//!   Uses the `rmcp` crate for MCP protocol handling.
//!
//! # Tools
//!
//! The live tool surface is generated into `docs/TOOLS.md` by `gen_tools_doc`.
//! Do not maintain a handwritten inventory here — it drifts from the real surface.
//!
//! ## Headless limitations
//! Debugger/UI/scripting features are not exposed in headless mode.

use std::path::PathBuf;

#[cfg(not(any(feature = "ida-92", feature = "ida-93", feature = "ida-94")))]
compile_error!("enable exactly one IDA SDK feature: ida-92, ida-93, or ida-94");
#[cfg(any(
    all(feature = "ida-92", feature = "ida-93"),
    all(feature = "ida-92", feature = "ida-94"),
    all(feature = "ida-93", feature = "ida-94"),
))]
compile_error!("IDA SDK features are mutually exclusive");

#[cfg(feature = "ida-92")]
pub extern crate idalib_92 as idalib;
#[cfg(feature = "ida-93")]
pub extern crate idalib_93 as idalib;
#[cfg(feature = "ida-94")]
pub extern crate idalib_94 as idalib;

pub mod address;
pub mod crash_guard;
pub mod disasm;
pub mod dsc;
pub mod error;
pub mod ida;
pub mod server;
pub mod skills;
pub mod supervisor;

/// The root-level commands the binary handles itself.
///
/// Lives here rather than in `main.rs` because two crates need the same answer:
/// the binary feeds it to `assert_management_matches_command`, and the library's
/// own tests check that no published tool name collides with one of these. When
/// it was a constant in `main.rs` plus copies in the tests, the copies drifted —
/// they still named `serve-http` after that command was merged into
/// `serve --mode`, and never gained `skills`, and nothing failed, because a copy
/// only feeds a collision check that a stale name cannot trip.
pub const MANAGEMENT_COMMANDS: &[&str] = &["serve", "worker", "probe", "skills"];

pub use error::ToolError;
pub use ida::{
    init_ida_library, run_ida_loop, AddressInfo, ApplyTypesSpec, BasicBlockInfo, BytesResult,
    DbInfo, ExportInfo, FunctionInfo, FunctionListResult, FunctionRangeInfo, IdaInitState,
    IdaRequest, IdaRuntimePolicy, IdaWorker, ImportInfo, OpenSpec, SegmentInfo, StringInfo,
    StringListResult, StringXrefInfo, StringXrefsResult, SymbolInfo, XRefInfo,
};
pub use server::catalog::ToolCategory;
pub use server::{IdaMcpServer, ServerMode};

/// Product name reported in MCP `serverInfo`.
///
/// Not `env!("CARGO_PKG_NAME")`: the three parallel per-SDK manifests are
/// named `ida-headless-mcp`, `-ida93` and `-ida94`, so the package name would
/// leak the build variant into the protocol identity. The binary is called
/// `ida-headless-mcp` in every manifest.
pub const SERVER_NAME: &str = "ida-headless-mcp";

/// Identity reported in MCP `serverInfo`.
///
/// Do **not** replace this with [`rmcp::model::Implementation::from_build_env`]:
/// that helper expands `env!("CARGO_CRATE_NAME")` and `env!("CARGO_PKG_VERSION")`
/// inside rmcp's own compilation unit, so a server using it self-reports as
/// `rmcp` at rmcp's version. The `env!` below has to be expanded here, in this
/// crate, to mean anything.
pub fn server_implementation() -> rmcp::model::Implementation {
    rmcp::model::Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")).with_title(format!(
        "IDA Pro headless MCP server (IDA SDK {COMPILED_IDA_VERSION})"
    ))
}

/// IDA SDK minor version selected for this build.
pub const COMPILED_IDA_VERSION: &str = if cfg!(feature = "ida-92") {
    "9.2"
} else if cfg!(feature = "ida-93") {
    "9.3"
} else {
    "9.4"
};

/// Expand a `~/` prefix to the user's home directory.
///
/// The one place this expansion is spelled. Both public faces reach it — the
/// worker's `open_idb` and the supervisor's `idb_open` — because a `~/` path
/// that opens through one and not the other is the same bug reported twice.
pub fn expand_path(path: &str) -> PathBuf {
    expand_path_with_home(path, home_dir().as_deref())
}

/// [`expand_path`] with the home directory supplied rather than read.
///
/// Exists so the expansion can be tested against a directory the test made,
/// instead of against whatever `$HOME` the developer running it happens to
/// have — and so no test has to mutate the process environment to say so.
pub(crate) fn expand_path_with_home(path: &str, home: Option<&std::ffi::OsStr>) -> PathBuf {
    match (home_relative(path), home) {
        (Some(relative), Some(home)) => PathBuf::from(home).join(relative),
        // No `~/`, or a `~/` with nowhere to point: the caller's string is
        // still the best answer, and the failure it produces names the path
        // the caller wrote.
        _ => PathBuf::from(path),
    }
}

/// The part of `path` that follows a home-directory prefix, if it has one.
///
/// Windows accepts `~\` as well, because that is how a Windows user writes a
/// path; `~name` is not expanded on any platform, since resolving another
/// user's home needs the account database rather than an environment variable.
fn home_relative(path: &str) -> Option<&str> {
    let rest = path.strip_prefix('~')?;
    #[cfg(windows)]
    {
        rest.strip_prefix(['/', '\\'])
    }
    #[cfg(not(windows))]
    {
        rest.strip_prefix('/')
    }
}

/// Where `~` points for this process.
///
/// `$HOME` everywhere, and `%USERPROFILE%` after it on Windows, where `$HOME`
/// is set by MSYS/Git-Bash style environments and absent from a plain console.
fn home_dir() -> Option<std::ffi::OsString> {
    if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
        return Some(home);
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").filter(|home| !home.is_empty())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Drop `None`, blank, and whitespace-only strings. The `&str` form avoids
/// allocating when the caller only needs a borrowed view.
pub(crate) fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::expand_path_with_home;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn a_tilde_path_lands_under_the_home_directory() {
        let home = OsStr::new("/isolated/home");
        assert_eq!(
            expand_path_with_home("~/samples/malware", Some(home)),
            PathBuf::from("/isolated/home").join("samples/malware")
        );
    }

    #[test]
    fn everything_else_is_passed_through_unchanged() {
        let home = Some(OsStr::new("/isolated/home"));
        for path in [
            "/absolute/sample.i64",
            "relative/sample.i64",
            "~",
            "~user/x",
        ] {
            assert_eq!(
                expand_path_with_home(path, home),
                PathBuf::from(path),
                "{path} must not be rewritten"
            );
        }
    }

    #[test]
    fn a_tilde_path_with_no_home_stays_as_the_caller_wrote_it() {
        // The open then fails naming `~/samples/x`, which is what the caller
        // typed. Substituting a guessed home would fail naming a path nobody
        // asked for.
        assert_eq!(
            expand_path_with_home("~/samples/x", None),
            PathBuf::from("~/samples/x")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_also_expands_the_backslash_spelling() {
        let home = OsStr::new(r"C:\Users\tester");
        assert_eq!(
            expand_path_with_home(r"~\samples\malware", Some(home)),
            PathBuf::from(r"C:\Users\tester").join(r"samples\malware")
        );
    }
}
