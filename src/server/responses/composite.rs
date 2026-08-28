//! Composite-tool output types.
//!
//! The types below are the *cross-engine baseline*. Unlike the rest of this
//! module they are not mirrors of a worker type: the composite tools assemble
//! them field by field from several worker calls, so the struct is both the
//! constructor and the schema and the two cannot drift.
//!
//! A second engine (Binary Ninja's `binary.survey` / `function.analyze`) is
//! expected to fill the same keys with the same meaning. Where an engine has no
//! equivalent for a key, it must omit it rather than invent a value: every
//! optional field below documents exactly when it is absent. Where an engine
//! wants to add a key, it belongs in `metadata` (file identity) or in a new
//! named block — never as a loose top-level scalar, because the top level is
//! the part clients pattern-match on.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::super::requests::{DiffAction, TraceDirection};
use super::controlflow::BasicBlockInfo;
use super::coverage::AnalysisCoverage;
use super::functions::FunctionInfo;
use super::metadata::SegmentInfo;
use super::types::FrameInfo;

/// File identity of a surveyed binary.
///
/// Cross-engine contract: fill from whatever the engine calls its binary view.
/// `path` is the input file the engine was pointed at (not the database file),
/// `module` is its file name, `image_size` is `max_address - min_address` and
/// not the on-disk size (`input_file_size` is that).
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyMetadata {
    /// Path of the analyzed input file; empty when the engine does not know it.
    pub path: String,
    /// File name component of `path`.
    pub module: String,
    /// Container format as the engine names it (`ELF`, `PE`, `MACHO`, ...).
    pub file_type: String,
    /// Processor module / architecture name.
    pub processor: String,
    /// Addressing width of the image: 16, 32 or 64.
    pub bits: u32,
    /// Preferred load address, hex-formatted; absent when the image has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_address: Option<String>,
    /// Lowest mapped address, hex-formatted.
    pub min_address: String,
    /// Highest mapped address, hex-formatted.
    pub max_address: String,
    /// `max_address - min_address`, hex-formatted.
    pub image_size: String,
    /// Size of the input file in bytes; absent when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_file_size: Option<u64>,
    /// MD5 of the input file, lowercase hex; absent when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    /// SHA-256 of the input file, lowercase hex; absent when unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Address of `main`, hex-formatted; absent when the engine did not find one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_address: Option<String>,
}

/// Whole-binary counts.
///
/// Cross-engine contract: `total_functions` and `total_strings` are database
/// totals even when the scan was capped, so they can exceed
/// `limits.functions_scanned` / `limits.strings_scanned`. Everything else is a
/// count over what was actually scanned — the engine would have to walk the
/// whole database to say more, which is the cost a bounded survey exists to
/// avoid. Check `limits` before comparing two of these numbers.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyStatistics {
    /// Functions in the database, whether or not they were scanned.
    pub total_functions: usize,
    /// Scanned functions carrying a real symbol.
    pub named_functions: usize,
    /// Scanned functions still on an engine-generated placeholder name
    /// (`sub_...` here).
    pub unnamed_functions: usize,
    /// Strings in the database, whether or not they were scanned.
    pub total_strings: usize,
    /// Segments / sections.
    pub total_segments: usize,
    /// Imported symbols seen (see `limits.imports_truncated`).
    pub total_imports: usize,
    /// Exported / public names seen (see `limits.exports_truncated`).
    pub total_exports: usize,
    /// Program entry points.
    pub total_entrypoints: usize,
}

/// One program entry point.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyEntrypoint {
    /// Entry address, hex-formatted.
    pub address: String,
    /// Name of the function at that address; absent when none was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Position in the engine's entry-point table, zero-based.
    pub ordinal: usize,
}

/// One string, ranked by how often it is referenced.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyString {
    /// Address of the first byte, hex-formatted.
    pub address: String,
    /// Decoded text.
    pub content: String,
    /// Length in bytes.
    pub length: usize,
    /// Number of references to the string.
    pub xref_count: u64,
}

/// One function, ranked by how central it looks in the binary.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyFunction {
    /// Entry address, hex-formatted.
    pub address: String,
    /// Symbol name.
    pub name: String,
    /// Size in bytes of the function's primary chunk.
    pub size: usize,
    /// References to the entry address, of any kind.
    pub xref_count: u64,
    /// Distinct functions that call this one.
    pub caller_count: u64,
    /// Distinct functions this one calls.
    pub callee_count: u64,
    /// Coarse shape, first match wins: `thunk` (8 bytes or fewer), `leaf` (no
    /// outgoing calls), `hub` (8 or more outgoing calls), else `normal`.
    pub kind: String,
}

/// One imported symbol, as bucketed by `imports_by_category`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyImport {
    /// Import slot address, hex-formatted.
    pub address: String,
    /// Imported symbol name.
    pub name: String,
    /// Library or segment the symbol comes from.
    pub module: String,
}

/// A function together with a call-graph degree, for the summary's extremes.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyFunctionDegree {
    /// Function entry address, hex-formatted.
    pub address: String,
    /// Function name.
    pub name: String,
    /// The degree that made this function the extreme.
    pub count: u64,
}

/// Shape of the call graph over the scanned functions.
///
/// Cross-engine contract: every count here is over the functions actually
/// scanned (`limits.functions_scanned`), never over the whole database, so a
/// truncated survey stays internally consistent.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyCallgraphSummary {
    /// Sum of outgoing call counts over the scanned functions.
    pub total_call_edges: u64,
    /// Scanned functions nothing calls — the roots to start reading from.
    pub root_function_count: usize,
    /// Names of the first `top` root functions.
    pub root_functions: Vec<String>,
    /// Scanned functions that call nothing.
    pub leaf_function_count: usize,
    /// The scanned function with the most callees; absent when none was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_out_degree: Option<SurveyFunctionDegree>,
    /// The scanned function with the most callers; absent when none was scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_in_degree: Option<SurveyFunctionDegree>,
}

/// What the survey was allowed to look at, and what it actually looked at.
///
/// Cross-engine contract: a composite tool must never quietly answer from a
/// partial scan. Every `*_truncated` flag here is the signal that a follow-up
/// paginated call (`list_funcs`, `strings`, `imports`) is needed.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyLimits {
    /// Detail level that ran: `standard` or `minimal`.
    pub detail: String,
    /// Cap applied to the function scan.
    pub max_functions_scanned: usize,
    /// Functions actually scanned.
    pub functions_scanned: usize,
    /// True when the database holds more functions than were scanned.
    pub functions_truncated: bool,
    /// Cap applied to the string scan.
    pub max_strings_scanned: usize,
    /// Strings actually scanned.
    pub strings_scanned: usize,
    /// True when the database holds more strings than were scanned.
    pub strings_truncated: bool,
    /// Cap applied to the import scan.
    pub max_imports_scanned: usize,
    /// Imports actually scanned.
    pub imports_scanned: usize,
    /// True when the scan stopped exactly on the cap and more may exist.
    pub imports_truncated: bool,
    /// Cap applied to the export/name scan.
    pub max_exports_scanned: usize,
    /// Exports actually scanned.
    pub exports_scanned: usize,
    /// True when the scan stopped exactly on the cap and more may exist.
    pub exports_truncated: bool,
    /// How many entries each `interesting_*` list and `root_functions` holds at most.
    pub highlight_limit: usize,
    /// True when the per-function metrics pass ran. False for `detail=minimal`
    /// and when the pass failed, in which case `metrics_error` says why.
    pub metrics_computed: bool,
    /// Why the metrics pass produced nothing; absent when it ran or was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_error: Option<String>,
}

/// `survey_binary` output — one call, whole-binary orientation.
///
/// Cross-engine baseline. A Binary Ninja `binary.survey` should answer with
/// exactly these top-level keys: `metadata`, `statistics`, `segments`,
/// `entrypoints`, `interesting_strings`, `interesting_functions`,
/// `imports_by_category`, `callgraph_summary`, `limits`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurveyBinaryOutput {
    /// File identity.
    pub metadata: SurveyMetadata,
    /// Whole-database counts.
    pub statistics: SurveyStatistics,
    /// Address-space layout.
    pub segments: Vec<SegmentInfo>,
    /// Program entry points, in engine order.
    pub entrypoints: Vec<SurveyEntrypoint>,
    /// Strings ordered by reference count, descending, capped at
    /// `limits.highlight_limit`. Absent when the metrics pass did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interesting_strings: Option<Vec<SurveyString>>,
    /// Functions ordered by reference count then size, descending, capped at
    /// `limits.highlight_limit`. Absent when the metrics pass did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interesting_functions: Option<Vec<SurveyFunction>>,
    /// Imports bucketed by a naive first-match-wins name heuristic. Keys are
    /// `crypto`, `network`, `registry`, `process`, `file_io`, `memory`,
    /// `string`, `time` and `other`; empty buckets are omitted entirely.
    pub imports_by_category: BTreeMap<String, Vec<SurveyImport>>,
    /// Call-graph shape. Absent when the metrics pass did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callgraph_summary: Option<SurveyCallgraphSummary>,
    /// Coverage of this survey — read it before trusting the counts above.
    pub limits: SurveyLimits,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One string constant referenced from inside an analyzed function.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionStringRef {
    /// Address of the string, hex-formatted.
    pub address: String,
    /// Decoded text.
    pub content: String,
    /// Length in bytes.
    pub length: usize,
    /// Addresses inside the function that reference it, hex-formatted.
    pub referenced_from: Vec<String>,
}

/// Everything `analyze_function` found about one target.
///
/// Cross-engine contract: `target` echoes the caller's input so a batch answer
/// can be correlated without positional assumptions. Every analysis block is
/// optional and each has a sibling `*_error`: a target whose decompilation
/// fails still returns its disassembly, callers and strings. A target that
/// could not be resolved to a function at all carries only `target` and
/// `error`.
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFunctionEntry {
    /// The target exactly as the caller wrote it.
    pub target: String,
    /// Resolved function entry address, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Function name; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// First address of the function, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    /// One past the last address of the function, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    /// `end - start`, in bytes; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// Decompiler pseudocode; absent when not requested or unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pseudocode: Option<String>,
    /// Why there is no pseudocode; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pseudocode_error: Option<String>,
    /// Instruction listing, one instruction per line, capped by
    /// `limits.max_instructions`; absent when not requested or unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly: Option<String>,
    /// Why there is no listing; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disassembly_error: Option<String>,
    /// Functions that call this one, capped by `limits.max_callers`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<Vec<FunctionInfo>>,
    /// How many callers exist, before the cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_count: Option<usize>,
    /// True when `callers` was cut by `limits.max_callers`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers_truncated: Option<bool>,
    /// Why there are no callers; absent when the lookup succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers_error: Option<String>,
    /// Functions this one calls, capped by `limits.max_callees`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees: Option<Vec<FunctionInfo>>,
    /// How many callees exist, before the cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_count: Option<usize>,
    /// True when `callees` was cut by `limits.max_callees`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees_truncated: Option<bool>,
    /// Why there are no callees; absent when the lookup succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees_error: Option<String>,
    /// Strings referenced from inside the function. Absent when not requested.
    ///
    /// Derived by intersecting the database's string cross-reference index
    /// with `[start, end)`, so it covers the strings the engine detected and
    /// nothing else — see `limits.strings_scanned`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referenced_strings: Option<Vec<FunctionStringRef>>,
    /// Stack frame layout; absent when not requested or the function has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_frame: Option<FrameInfo>,
    /// Why there is no frame; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_frame_error: Option<String>,
    /// Control-flow graph nodes, capped by `limits.max_blocks`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_blocks: Option<Vec<BasicBlockInfo>>,
    /// How many blocks the function has, before the cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_block_count: Option<usize>,
    /// True when `basic_blocks` was cut by `limits.max_blocks`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_blocks_truncated: Option<bool>,
    /// Why there is no graph; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_blocks_error: Option<String>,
    /// Why this target produced nothing at all; absent when it resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What `analyze_function` was allowed to look at.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFunctionLimits {
    /// Cap on how many targets one call may analyze.
    pub max_targets: usize,
    /// Targets actually analyzed.
    pub targets_analyzed: usize,
    /// True when the caller asked for more targets than the cap allows.
    pub targets_truncated: bool,
    /// Cap on instructions per disassembly listing.
    pub max_instructions: usize,
    /// Cap on entries in `callers`.
    pub max_callers: usize,
    /// Cap on entries in `callees`.
    pub max_callees: usize,
    /// Cap on entries in `basic_blocks`.
    pub max_blocks: usize,
    /// Cap applied to the string index scan that backs `referenced_strings`.
    pub max_strings_scanned: usize,
    /// Strings actually scanned; 0 when `include_strings` was false.
    pub strings_scanned: usize,
    /// True when the database holds more strings than were scanned, so
    /// `referenced_strings` may be incomplete.
    pub strings_truncated: bool,
    /// Why the string index scan produced nothing, when `include_strings` was
    /// on and it failed; absent when it ran or was not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings_error: Option<String>,
}

/// `analyze_function` output — one call, one dossier per target.
///
/// Cross-engine baseline. Always an object with `results` and `limits`, even
/// for a single target: a fixed shape is worth one extra nesting level, and it
/// subsumes what a separate batch tool would have been.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeFunctionOutput {
    /// One entry per requested target, in request order.
    pub results: Vec<AnalyzeFunctionEntry>,
    /// Coverage of this analysis — read it before trusting the lists above.
    pub limits: AnalyzeFunctionLimits,
}

/// Compact callee in an `analyze_component` function summary.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentCallee {
    /// Callee entry address, hex-formatted.
    pub addr: String,
    /// Callee name.
    pub name: String,
}

/// Compact per-function summary inside `analyze_component`.
///
/// No decompilation, no instruction listing, and no prototype: this crate's
/// `FunctionRangeInfo` does not carry one, and the tool does not call
/// `infer_types` to invent it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentFunctionSummary {
    /// Function entry address, hex-formatted.
    pub addr: String,
    /// Function name.
    pub name: String,
    /// `end - start`, in bytes.
    pub size: usize,
    /// Distinct callees, each as `{addr, name}`.
    pub callees: Vec<ComponentCallee>,
    /// String values referenced from inside the function, capped at
    /// `limits.max_strings_per_function`.
    pub strings: Vec<String>,
    /// Number of basic blocks. Complexity is computed from the full graph
    /// even when data-xref collection walks only block starts.
    pub basic_blocks: usize,
    /// Cyclomatic complexity `E - N + 2` (`N` = block count, `E` = successor
    /// edges). `0` when the function has no blocks.
    pub complexity: usize,
}

/// One internal call edge: component function `from` calls component function `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentCallEdge {
    /// Caller entry address, hex-formatted.
    pub from: String,
    /// Callee entry address, hex-formatted.
    pub to: String,
    /// Callee name.
    pub name: String,
}

/// Call graph restricted to the requested component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentCallGraph {
    /// Entry addresses of the component functions, hex-formatted, in request order.
    pub nodes: Vec<String>,
    /// Calls whose both ends sit inside `nodes`.
    pub edges: Vec<ComponentCallEdge>,
}

/// A data address referenced by at least two component functions.
///
/// Data xrefs are collected from each function's start and each basic-block
/// start, not from every instruction, so this list is an approximation.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedGlobal {
    /// Data address, hex-formatted.
    pub addr: String,
    /// Symbol name when `addr_info` reports an exact name; otherwise the hex address.
    pub name: String,
    /// Component function names that referenced this address, sorted.
    pub accessed_by: Vec<String>,
}

/// What `analyze_component` was allowed to look at.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeComponentLimits {
    /// Cap on how many distinct functions one call may analyze.
    pub max_targets: usize,
    /// Distinct functions actually analyzed.
    pub targets_analyzed: usize,
    /// True when the caller named more distinct functions than the cap allows.
    pub targets_truncated: bool,
    /// Cap on string values listed per function summary.
    pub max_strings_per_function: usize,
    /// Cap applied to the string index scan that backs `strings` / `string_usage`.
    pub max_strings_scanned: usize,
    /// Strings actually scanned; 0 when the scan did not run.
    pub strings_scanned: usize,
    /// True when the database holds more strings than were scanned.
    pub strings_truncated: bool,
    /// Why the string index scan produced nothing; absent when it ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings_error: Option<String>,
    /// Cap applied to each `xrefs_from` page used for shared-global discovery.
    pub max_data_xrefs_per_site: usize,
    /// True when any site's data-xref page was truncated, so `shared_globals`
    /// may be incomplete.
    pub data_xrefs_truncated: bool,
}

/// `analyze_component` output — related functions as one group.
///
/// Cross-engine baseline, not a Python drop-in: no `prototype`, no decompile,
/// no full disassembly, and `shared_globals` is built from data xrefs at
/// function/block starts rather than every instruction.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeComponentOutput {
    /// Compact summary per component function, in request order.
    pub functions: Vec<ComponentFunctionSummary>,
    /// Calls whose both ends sit inside the component.
    pub internal_call_graph: ComponentCallGraph,
    /// Data addresses referenced by at least two component functions.
    pub shared_globals: Vec<SharedGlobal>,
    /// Component functions that have at least one caller outside the component
    /// (an unresolvable caller address counts as outside).
    pub interface_functions: Vec<String>,
    /// Component functions whose known callers all sit inside the component.
    pub internal_only: Vec<String>,
    /// Strings referenced by at least two component functions, mapped to the
    /// sorted function names that use them.
    pub string_usage: BTreeMap<String, Vec<String>>,
    /// Coverage of this analysis — read it before trusting the lists above.
    pub limits: AnalyzeComponentLimits,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means `shared_globals` and
    /// `string_usage` are systematically small, not just incomplete at the
    /// edges: those two lists only emit entries seen on ≥2 functions, so a
    /// partial index drops them entirely rather than shrinking them.
    pub analysis_coverage: AnalysisCoverage,
}

/// `diff_before_after` output — one edit, two decompiles.
///
/// No `analysis_coverage`: the interesting answer is the mutation plus the
/// two Hex-Rays snapshots, not an analysis index.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffBeforeAfterOutput {
    /// Function entry that was edited, hex-formatted.
    pub address: String,
    /// Function name as resolved before the mutation.
    pub name: String,
    /// Mutation that was requested.
    pub action: DiffAction,
    /// True when the mutation was accepted by IDA.
    pub action_applied: bool,
    /// Decompiler output before the mutation; absent when that decompile failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Decompiler output after the mutation; absent when that decompile failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// True when both decompiles succeeded and the text differs.
    pub changes_detected: bool,
    /// Why there is no `before`; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_error: Option<String>,
    /// Why there is no `after`; absent when there is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_error: Option<String>,
    /// Non-fatal follow-up (e.g. mark_cfunc_dirty failed); absent when none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_error: Option<String>,
}

/// Code vs data classification on a `trace_data_flow` node or edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TraceRefKind {
    Code,
    Data,
}

/// One address visited by `trace_data_flow`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceDataFlowNode {
    /// The address, hex-formatted.
    pub addr: String,
    /// Enclosing function name; absent outside any function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub func: Option<String>,
    /// One-instruction listing; absent when disassembly failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    /// `code` when the address sits in a function, otherwise `data`.
    pub r#type: TraceRefKind,
    /// Symbol name, or the enclosing function name if there is no symbol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// BFS distance from the start address.
    pub depth: usize,
}

/// One xref hop in a `trace_data_flow` walk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceDataFlowEdge {
    /// Referencing address, hex-formatted.
    pub from: String,
    /// Referenced address, hex-formatted.
    pub to: String,
    /// `code` when the xref is a code reference, otherwise `data`.
    pub r#type: TraceRefKind,
}

/// Caps `trace_data_flow` advertised and applied.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceDataFlowLimits {
    /// Depth this call walked to.
    pub max_depth: usize,
    /// Hard cap on nodes (200).
    pub max_nodes: usize,
    /// Hard cap on edges (500).
    pub max_edges: usize,
    /// True when a node was dropped because `max_nodes` was hit.
    pub nodes_truncated: bool,
    /// True when an edge was dropped because `max_edges` was hit.
    pub edges_truncated: bool,
    /// True when any per-node xref page reported `truncated`.
    pub xrefs_truncated: bool,
}

/// `trace_data_flow` output — a bounded BFS over xrefs, not a call graph.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceDataFlowOutput {
    /// Start address, hex-formatted.
    pub start: String,
    /// Walk direction that was applied.
    pub direction: TraceDirection,
    /// Largest node depth actually reached.
    pub depth_reached: usize,
    /// Visited addresses, start first.
    pub nodes: Vec<TraceDataFlowNode>,
    /// Xref hops that were recorded.
    pub edges: Vec<TraceDataFlowEdge>,
    /// Coverage of this walk — read it before trusting the lists above.
    pub limits: TraceDataFlowLimits,
    /// Whether analysis had settled when this answer was read.
    pub analysis_coverage: AnalysisCoverage,
}

/// One `func_profile` target.
///
/// No prototype, no instruction listing, no decompile: this tool only
/// spends the cheap worker calls (`function_at`, `callers`, `callees`,
/// `basic_blocks`, plus one shared string-index scan).
#[derive(Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FuncProfileEntry {
    /// The target exactly as the caller wrote it.
    pub target: String,
    /// Resolved function entry, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Function name; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `end - start`, in bytes; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    /// How many callers exist; absent when that lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_count: Option<usize>,
    /// How many callees exist; absent when that lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_count: Option<usize>,
    /// How many basic blocks the function has; absent when that lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_block_count: Option<usize>,
    /// Cyclomatic complexity `E - N + 2`; absent when the CFG was not read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<usize>,
    /// Distinct strings referenced from `[start, end)`; absent when the
    /// string-index scan did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_ref_count: Option<usize>,
    /// Callers, capped by `limits.max_items`; absent when `include_lists` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<Vec<FunctionInfo>>,
    /// Callees, capped by `limits.max_items`; absent when `include_lists` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees: Option<Vec<FunctionInfo>>,
    /// String contents referenced from the function, capped by `limits.max_items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<String>>,
    /// True when `callers` was cut by `limits.max_items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers_truncated: Option<bool>,
    /// True when `callees` was cut by `limits.max_items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees_truncated: Option<bool>,
    /// True when `strings` was cut by `limits.max_items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings_truncated: Option<bool>,
    /// Why this target produced nothing at all; absent when it resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What `func_profile` was allowed to look at.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FuncProfileLimits {
    /// Cap on how many targets one call may profile.
    pub max_targets: usize,
    /// Targets actually profiled.
    pub targets_analyzed: usize,
    /// True when the caller asked for more targets than the cap allows.
    pub targets_truncated: bool,
    /// Cap applied to each included list.
    pub max_items: usize,
    /// Cap applied to the string index scan.
    pub max_strings_scanned: usize,
    /// Strings actually scanned; 0 when the scan did not run.
    pub strings_scanned: usize,
    /// True when the database holds more strings than were scanned.
    pub strings_truncated: bool,
    /// Why the string index scan produced nothing; absent when it ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings_error: Option<String>,
}

/// `func_profile` output — a cheap single-function overview.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FuncProfileOutput {
    /// One entry per requested target, in request order.
    pub results: Vec<FuncProfileEntry>,
    /// Coverage of this profile — read it before trusting the counts above.
    pub limits: FuncProfileLimits,
    /// Whether analysis had settled when this answer was read.
    pub analysis_coverage: AnalysisCoverage,
}
