//! Database identity, open/close lifecycle, and DSC output types.
//!
//! These DSC / open payloads are assembled with `json!` rather than a worker
//! struct (except the two DSC image/region records), so the types below
//! describe the bytes on the wire rather than mirroring a Rust type. A tighter
//! schema would be a lie: several of them have two arms.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::{AnalysisCoverage, AnalysisStatusOutput};

/// `idb_meta` output.
///
/// Everything is derived from the *input file* the database was built from,
/// not from the `.i64` on disk. `base_address` and `main_address` are null
/// rather than absent when IDA has no answer for them.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdbMetaOutput {
    /// Container format as IDA names it (`ELF`, `PE`, `MACHO`, ...).
    pub file_type: String,
    /// Processor module long name.
    pub processor: String,
    /// Addressing width of the image: 16, 32 or 64.
    pub bits: u32,
    /// Functions the database knows about.
    pub function_count: usize,
    /// Path of the analyzed input file, trailing NULs trimmed.
    pub input_file_path: String,
    /// Size of the input file in bytes.
    pub input_file_size: u64,
    /// MD5 of the input file, lowercase hex.
    pub md5: String,
    /// SHA-256 of the input file, lowercase hex.
    pub sha256: String,
    /// Preferred load address, hex-formatted; null when the image has none.
    pub base_address: Option<String>,
    /// Lowest mapped address, hex-formatted.
    pub min_address: String,
    /// Highest mapped address, hex-formatted.
    pub max_address: String,
    /// Address of `main`, hex-formatted; null when IDA did not find one.
    pub main_address: Option<String>,
    /// Worker session that answered; absent on the worker's own MCP face.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// Outcome of an external debug-info load performed during `open_idb`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugInfoLoad {
    /// Path that was loaded from.
    pub path: String,
    /// True when IDA accepted the debug info.
    pub loaded: bool,
    /// Why the load failed; null when it succeeded.
    pub error: Option<String>,
}

/// `load_debug_info` output.
///
/// Note this is *not* [`DebugInfoLoad`]: the standalone tool reports a failure
/// as `isError`, so it never carries an `error` field alongside a result.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoadDebugInfoOutput {
    /// Path that was loaded from, after resolving a sibling `.dSYM`.
    pub path: String,
    /// True when IDA accepted the debug info.
    pub loaded: bool,
}

/// `open_idb` output.
///
/// The first eight fields are always present. The rest arrive in two
/// conditional groups, and which ones you see says something about how the
/// server is deployed:
///
/// - **Session and ownership** (`session_id`, `close_*`) appear on every face
///   except the worker's own stdio MCP face. `close_token` is only minted for
///   an HTTP context that took ownership; a context that did *not* get
///   ownership sees `close_owner_session_id` and `close_recovery_hint`
///   instead, and `close_hint` explains the situation either way.
/// - **Background analysis** (`analysis_*`) appears only when the input was
///   large enough to route auto-analysis to a task. `analysis_task_id` plus
///   `analysis_background_reason` means it started; `analysis_background_error`
///   means it did not, and analysis has not run at all.
///
/// A client that wants to know whether the database is ready should read
/// `analysis_status.auto_is_ok`, not the presence of these keys.
///
/// Both conditional groups are gated on the server running in something other
/// than `ServerMode::Worker`. Every entry point builds the worker face — the
/// supervisor owns sessions, lifecycle and the `idb_open` tool — so in
/// practice a client sees only the eight always-present fields. They stay in
/// the schema because the branches are live code and are where a future
/// non-worker face would surface.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenIdbOutput {
    /// Path of the database that is now open — the `.i64`, not the raw input.
    pub path: String,
    /// Container format as IDA names it (`ELF`, `PE`, `MACHO`, ...).
    pub file_type: String,
    /// Processor module long name.
    pub processor: String,
    /// Addressing width of the image: 16, 32 or 64.
    pub bits: u32,
    /// Functions the database knows about right after opening.
    pub function_count: usize,
    /// Outcome of the debug-info load; null when none was requested.
    pub debug_info: Option<DebugInfoLoad>,
    /// Auto-analysis state. The nested copy never carries `session_id`.
    pub analysis_status: AnalysisStatusOutput,
    /// Tool names worth calling next, narrowed by whether analysis has settled.
    pub quick_tools: Vec<String>,
    /// Worker session that owns the database; absent on the worker's own face.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// What to do about closing this database; absent on the worker's own face.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_hint: Option<String>,
    /// Token that authorizes `close_idb`; absent unless this context owns the database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_token: Option<String>,
    /// True when an existing token was handed back rather than a new one minted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_token_reused: Option<bool>,
    /// HTTP context that owns the database; absent when ownership is unclaimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_owner_session_id: Option<String>,
    /// How to close a database whose token was lost; absent when this context owns it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_recovery_hint: Option<String>,
    /// True when auto-analysis was routed to a background task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_background: Option<bool>,
    /// True when that task is running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_started: Option<bool>,
    /// Task id to poll with `task_status`; absent when no task started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_task_id: Option<String>,
    /// `started`, `already_running`, or `not_started`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_task_status: Option<String>,
    /// Why analysis was moved off the request path; absent when it was not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_background_reason: Option<String>,
    /// Why the background task could not be created; absent when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_background_error: Option<String>,
}

/// `analyze_funcs` output.
///
/// Running analysis inline fills `completed`/`function_count`;
/// `background=true` hands back `status`/`task_id`/`message` instead and the
/// work continues after the call returns.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFuncsOutput {
    /// True when auto-analysis reached a settled state; inline runs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    /// Functions the database knows about afterwards; inline runs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_count: Option<usize>,
    /// `started` or `already_running`; background runs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Task id to poll with `task_status`; background runs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// What to do next; background runs only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `task_status` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskStatusOutput {
    /// The task id that was polled.
    pub task_id: String,
    /// `running`, `completed`, `failed` or `cancelled`.
    pub status: String,
    /// Latest progress line the task reported.
    pub message: String,
    /// Seconds since the task was created.
    pub elapsed_secs: u64,
    /// Whatever the task produced, in that tool's own shape; absent until the
    /// task settles. For `analyze_funcs` this is its inline payload, and for a
    /// failed task it is the tool-error result the work returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// `close_idb` output.
///
/// A refused close (HTTP session that does not own the database and supplied
/// no token) fills `reason`/`owner_session_id`/`hint` instead of closing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloseIdbOutput {
    /// True when the database was closed.
    pub closed: bool,
    /// Why the close was refused; absent when `closed` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The HTTP session that currently owns the database.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_session_id: Option<String>,
    /// How to close it anyway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// One image `dsc_add_dylib` / `open_dsc` loaded from the shared cache.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscImageInfo {
    pub index: i32,
    pub name: String,
    pub file_name: String,
    pub address: String,
    pub address_value: u64,
    pub total_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_index: Option<u64>,
    pub loaded: bool,
}

/// One region `dsc_add_region` mapped from the shared cache.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscRegionInfo {
    pub start: String,
    pub start_value: u64,
    pub size: u64,
    pub kind: String,
    pub image_index: i32,
    pub name: String,
    pub loaded: bool,
}

/// `dsc_add_dylib` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscAddDylibOutput {
    pub success: bool,
    /// Absolute path of the dylib that was requested.
    pub module: String,
    pub message: String,
    /// `dscu` on a successful load.
    pub dsc_backend: String,
    pub image: DscImageInfo,
    /// Auto-analysis state after the load; null when the status query failed.
    pub analysis_status: Option<AnalysisStatusOutput>,
    /// `auto_is_ok` of that status; null when status is null.
    pub analysis_ready: Option<bool>,
    pub next_steps: Vec<String>,
}

/// `dsc_add_region` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscAddRegionOutput {
    pub success: bool,
    /// Requested address, hex-formatted.
    pub address: String,
    pub address_value: u64,
    pub message: String,
    pub dsc_backend: String,
    pub region: DscRegionInfo,
    pub analysis_status: Option<AnalysisStatusOutput>,
    pub analysis_ready: Option<bool>,
    pub next_steps: Vec<String>,
}

/// `dsc_list_images` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscImageListOutput {
    /// Images in this page.
    pub images: Vec<DscImageInfo>,
    /// Matches before pagination, over the whole cache.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// The dyld_shared_cache backing this database, as IDA recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_file_path: Option<String>,
}

/// `dsc_image_deps` output. `images` includes the queried image itself.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscImageDepsOutput {
    pub images: Vec<DscImageInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// The image whose dependency closure this is.
    pub module: String,
    /// Recursion depth that produced it; -1 means unlimited.
    pub depth: i32,
}

/// One `dsc_find_symbols` hit.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscSymbolMatch {
    pub symbol: String,
    pub address: String,
    pub address_value: u64,
    /// -1 when the hit came from the cache's own `.symbols` table rather than
    /// an image's export table.
    pub image_index: i32,
    /// Absent for cache-local hits (`image_index == -1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
}

/// `dsc_find_symbols` output.
///
/// No total: IDA stops collecting at the count it was given, so the only honest
/// statement about the remainder is whether one exists.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscFindSymbolsOutput {
    pub matches: Vec<DscSymbolMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// One `dsc_find_strings` hit.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscStringMatch {
    pub address: String,
    pub address_value: u64,
    pub image_index: i32,
    pub file_index: u64,
    pub file_offset: u64,
    pub context: String,
}

/// `dsc_find_strings` output. No total, for the reason in
/// [`DscFindSymbolsOutput`].
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscFindStringsOutput {
    pub matches: Vec<DscStringMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// `dsc_region_at` output: what `dsc_add_region` would map, without mapping it.
///
/// Carries no `loaded`, unlike [`DscRegionInfo`]: IDA's query path does not
/// report it, so the field would be a constant rather than an answer.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DscRegionAtOutput {
    pub start: String,
    pub start_value: u64,
    pub size: u64,
    pub kind: String,
    pub image_index: i32,
    pub name: String,
}

/// `open_dsc` output.
///
/// Two arms: a background start (`status`/`task_id`/`message`) and a
/// completed open (the `DbInfo` fields plus the DSC extras). Same close
/// metadata convention as [`OpenIdbOutput`].
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenDscOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfoLoad>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_status: Option<AnalysisStatusOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frameworks_loaded: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_info: Option<DscImageInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsc_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loaded_images: Option<Vec<DscImageInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsc_warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_steps: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_token_reused: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_owner_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_recovery_hint: Option<String>,
}
