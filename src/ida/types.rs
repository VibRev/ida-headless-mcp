//! Response types for IDA worker operations.

use serde::{Deserialize, Serialize};

/// What to open. Timeout, progress, and cancel stay on the call — they are
/// transport concerns, not part of the database identity.
#[derive(Debug, Clone, Default)]
pub struct OpenSpec {
    pub path: String,
    pub load_debug_info: bool,
    pub debug_info_path: Option<String>,
    pub debug_info_verbose: bool,
    pub force: bool,
    pub rebuild: bool,
    pub file_type: Option<String>,
    pub auto_analyse: bool,
    pub extra_args: Vec<String>,
    pub idb_out: Option<String>,
}

/// Arguments for `apply_types`. The bools are not interchangeable; a struct
/// literal at the call site is the only way to keep them named.
#[derive(Debug, Clone, Default)]
pub struct ApplyTypesSpec {
    pub addr: Option<u64>,
    pub name: Option<String>,
    pub offset: i64,
    pub stack_offset: Option<i64>,
    pub stack_name: Option<String>,
    pub decl: Option<String>,
    pub type_name: Option<String>,
    pub relaxed: bool,
    pub delay: bool,
    pub strict: bool,
}

/// Database info returned after opening
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DbInfo {
    pub path: String,
    pub file_type: String,
    pub processor: String,
    pub bits: u32,
    pub function_count: usize,
    pub debug_info: Option<DebugInfoLoad>,
    pub analysis_status: AnalysisStatus,
}

/// Opaque identity for one database-open lifetime within a worker backend.
///
/// A background task captures this at open and passes it back for every later
/// operation on that database, so a close/reopen cannot silently redirect the
/// task's remaining work onto whatever database is current. It scopes both
/// cleanup (a stale task may close the database it opened, never a newer one)
/// and post-open work (a stale task must not read or mutate a newer one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseGeneration(pub(crate) u64);

/// Internal open result that carries the database lifetime identity without
/// exposing it in the public MCP tool response.
#[derive(Debug, Clone)]
pub struct OpenedDatabase {
    pub(crate) info: DbInfo,
    pub(crate) generation: DatabaseGeneration,
}

/// Result of closing only when an expected database lifetime is still active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalCloseResult {
    Closed,
    NotCurrent,
}

/// One warmup step reported by `idb_open`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WarmupStep {
    pub step: String,
    pub ok: bool,
    pub ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl WarmupStep {
    pub fn ok(step: impl Into<String>, ms: u64) -> Self {
        Self {
            step: step.into(),
            ok: true,
            ms,
            error: None,
        }
    }

    pub fn err(step: impl Into<String>, ms: u64, error: impl Into<String>) -> Self {
        Self {
            step: step.into(),
            ok: false,
            ms,
            error: Some(error.into()),
        }
    }
}

/// Worker-side warmup result. Session may prepend an `auto_wait` step.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WarmupResult {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
    pub steps: Vec<WarmupStep>,
}

impl WarmupResult {
    pub fn from_steps(steps: Vec<WarmupStep>) -> Self {
        let ok = steps.iter().all(|step| step.ok);
        Self {
            ok,
            reused: false,
            steps,
        }
    }

    pub fn reused() -> Self {
        Self {
            ok: true,
            reused: true,
            steps: Vec::new(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            serde_json::json!({
                "ok": false,
                "steps": [],
                "error": "failed to serialize warmup result",
            })
        })
    }
}

#[cfg(test)]
mod warmup_json_tests {
    use super::{WarmupResult, WarmupStep};
    use serde_json::{json, Value};

    #[test]
    fn warmup_json_roundtrip_keeps_ms_and_optional_error() {
        let result = WarmupResult::from_steps(vec![
            WarmupStep::ok("build_caches", 12),
            WarmupStep::err("init_hexrays", 3, "Hex-Rays decompiler is not available"),
        ]);
        assert!(!result.ok);

        let value = serde_json::to_value(&result).expect("serialize warmup");
        assert_eq!(value["ok"], false);
        assert!(value.get("reused").is_none());
        assert_eq!(
            value["steps"],
            json!([
                {"step": "build_caches", "ok": true, "ms": 12},
                {
                    "step": "init_hexrays",
                    "ok": false,
                    "ms": 3,
                    "error": "Hex-Rays decompiler is not available"
                }
            ])
        );
        assert!(value["steps"][0].get("native").is_none());
        assert!(value["steps"][1].get("lazy").is_none());

        let parsed: WarmupResult = serde_json::from_value(value).expect("parse warmup");
        assert_eq!(parsed, result);
    }

    #[test]
    fn reused_warmup_json_has_empty_steps() {
        let value = WarmupResult::reused().to_json();
        assert_eq!(value, json!({"ok": true, "reused": true, "steps": []}));
        let parsed: WarmupResult = serde_json::from_value(value).expect("parse reused warmup");
        assert!(parsed.ok);
        assert!(parsed.reused);
        assert!(parsed.steps.is_empty());
    }

    #[test]
    fn empty_warmup_is_ok_without_claiming_steps() {
        let value = WarmupResult::from_steps(Vec::new()).to_json();
        assert_eq!(value, json!({"ok": true, "steps": []}));
        assert!(value.get("reused").is_none());
        let steps = value["steps"].as_array().expect("steps array");
        assert!(steps.iter().all(|step| {
            step.get("step").and_then(Value::as_str) != Some("build_caches")
                && step.get("step").and_then(Value::as_str) != Some("init_hexrays")
        }));
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DebugInfoLoad {
    pub path: String,
    pub loaded: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnalysisStatus {
    pub auto_enabled: bool,
    pub auto_is_ok: bool,
    pub auto_state: String,
    pub auto_state_id: i32,
    pub analysis_running: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscRegionInfo {
    pub start: String,
    pub start_value: u64,
    pub size: u64,
    pub kind: String,
    pub image_index: i32,
    pub name: String,
    pub loaded: bool,
}

/// `dsc_list_images` result.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscImageList {
    pub images: Vec<DscImageInfo>,
    /// Matches before pagination, over the whole cache.
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// The dyld_shared_cache backing this database, as IDA recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_file_path: Option<String>,
}

/// `dsc_image_deps` result.
///
/// `images` includes the queried image itself — IDA's `get_image_dependencies`
/// puts it in the output.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscImageDeps {
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
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// `dsc_find_symbols` result.
///
/// No `total`: IDA's `find_symbol` stops collecting at the count it was given,
/// so the only honest statement about the remainder is whether one exists —
/// which is what `next_offset` says.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscSymbolMatches {
    pub matches: Vec<DscSymbolMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// One `dsc_find_strings` hit.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscStringMatch {
    pub address: String,
    pub address_value: u64,
    pub image_index: i32,
    pub file_index: u64,
    pub file_offset: u64,
    pub context: String,
}

/// `dsc_find_strings` result. No `total`, for the reason in [`DscSymbolMatches`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscStringMatches {
    pub matches: Vec<DscStringMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// `dsc_region_at` result: what `dsc_add_region` would map, without mapping it.
///
/// Deliberately not [`DscRegionInfo`]. That type carries `loaded`, and idalib
/// hardcodes it to false on the query path (`idalib_dscu_get_region_by_ea`),
/// so reporting it here would be a lie rather than a lookup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DscRegionQuery {
    pub start: String,
    pub start_value: u64,
    pub size: u64,
    pub kind: String,
    pub image_index: i32,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: String,
    pub delta: i64,
    pub exact: bool,
    pub is_public: bool,
    pub is_weak: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionRangeInfo {
    pub address: String,
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressInfo {
    pub address: String,
    pub segment: Option<SegmentInfo>,
    pub function: Option<FunctionRangeInfo>,
    pub symbol: Option<SymbolInfo>,
}

/// Function info for listing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionInfo {
    pub address: String,
    pub name: String,
    pub size: usize,
}

/// Paginated function list result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FunctionListResult {
    pub functions: Vec<FunctionInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Segment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SegmentInfo {
    pub name: String,
    pub start: String,
    pub end: String,
    pub size: usize,
    pub permissions: String,
    pub r#type: String,
    pub bitness: u32,
}

/// String info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringInfo {
    pub address: String,
    pub content: String,
    pub length: usize,
}

/// String list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringListResult {
    pub strings: Vec<StringInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringXrefInfo {
    pub address: String,
    pub content: String,
    pub length: usize,
    pub xrefs: Vec<String>,
    pub xref_count: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StringXrefsResult {
    pub strings: Vec<StringXrefInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Local type info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalTypeInfo {
    pub ordinal: u32,
    pub name: String,
    pub decl: String,
    pub kind: String,
}

/// Local types list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalTypeListResult {
    pub types: Vec<LocalTypeInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Frame range info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameRange {
    pub start: String,
    pub end: String,
}

/// Stack frame member info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameMemberInfo {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
    pub part: String,
}

/// Stack frame info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FrameInfo {
    pub address: String,
    pub frame_size: u64,
    pub ret_size: i32,
    pub frsize: u64,
    pub frregs: u16,
    pub argsize: u64,
    pub fpd: u64,
    pub args_range: FrameRange,
    pub retaddr_range: FrameRange,
    pub savregs_range: FrameRange,
    pub locals_range: FrameRange,
    pub member_count: u32,
    pub members: Vec<FrameMemberInfo>,
}

/// Struct summary info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructSummary {
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub is_union: bool,
    pub member_count: u32,
}

/// Struct list result with pagination
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructListResult {
    pub structs: Vec<StructSummary>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Struct member info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructMemberInfo {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
}

/// Struct detailed info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructInfo {
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub is_union: bool,
    pub member_count: u32,
    pub members: Vec<StructMemberInfo>,
}

/// Struct member value
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructMemberValue {
    pub name: String,
    pub type_name: String,
    pub offset_bits: u64,
    pub size_bits: u64,
    pub offset: u64,
    pub size: u64,
    pub is_bitfield: bool,
    pub bytes: String,
}

/// Struct read result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StructReadResult {
    pub address: String,
    pub ordinal: u32,
    pub name: String,
    pub size: u64,
    pub members: Vec<StructMemberValue>,
}

/// Cross-reference info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XRefInfo {
    pub from: String,
    pub to: String,
    pub r#type: String,
    pub is_code: bool,
    /// The function the reference comes from, when `include_function` asked
    /// for it. Absent rather than null so the default answer keeps its shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<FunctionRef>,
}

/// A function named by address, for embedding in another answer.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FunctionRef {
    pub address: String,
    pub name: String,
}

/// Paginated cross-reference listing.
///
/// `truncated` is true when more references exist beyond `limit`; in that case
/// `next_offset` carries the offset to pass on the next call to page through
/// the remaining references. High-frequency targets can have enormous xref
/// counts, so enumeration is always bounded.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XRefListResult {
    pub xrefs: Vec<XRefInfo>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Declared type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeclareTypeResult {
    pub code: i32,
    pub name: String,
    pub decl: String,
    pub kind: String,
    pub replaced: bool,
}

/// Declare multiple types result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeclareTypesResult {
    pub errors: i32,
}

/// Applied type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplyTypeResult {
    pub address: String,
    pub applied: bool,
    pub source: String,
}

/// Guess type result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GuessTypeResult {
    pub address: String,
    pub code: i32,
    pub status: String,
    pub decl: String,
    pub kind: String,
}

/// Stack variable operation result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StackVarResult {
    pub function: String,
    pub name: String,
    pub offset: i64,
    pub code: i32,
    pub status: String,
}

/// Xrefs to a struct field
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XrefsToFieldResult {
    pub struct_ordinal: u32,
    pub struct_name: String,
    pub member_index: u32,
    pub member_name: String,
    pub member_type: String,
    pub member_offset_bits: u64,
    pub member_size_bits: u64,
    pub tid: String,
    pub xrefs: Vec<XRefInfo>,
    pub truncated: bool,
}

/// Import info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImportInfo {
    pub address: String,
    pub name: String,
    pub module: String,
    pub ordinal: usize,
}

/// Paginated import list result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImportListResult {
    pub imports: Vec<ImportInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Export/Name info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExportInfo {
    pub address: String,
    pub name: String,
    pub is_public: bool,
}

/// Paginated export list result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExportListResult {
    pub exports: Vec<ExportInfo>,
    pub total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// Global variable/name info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalInfo {
    pub address: String,
    pub name: String,
    pub is_public: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_weak: Option<bool>,
}

/// Basic block info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BasicBlockInfo {
    pub start: String,
    pub end: String,
    pub size: usize,
    pub block_type: String,
    pub successors: Vec<String>,
    pub predecessors: Vec<String>,
}

/// Bytes result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BytesResult {
    pub address: String,
    pub bytes: String,
    pub length: usize,
}
