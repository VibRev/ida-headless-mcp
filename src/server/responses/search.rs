//! String-index and pattern-scan output types.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;

/// One extracted string.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StringInfo {
    /// Address of the first byte, hex-formatted.
    pub address: String,
    /// Decoded text.
    pub content: String,
    /// Length in bytes as IDA measured it.
    pub length: usize,
}

/// Paginated string listing.
///
/// A call with `offset: 0` rebuilds IDA's string index first, so `total` counts
/// the database as it stands now rather than as the loader guessed it before
/// auto-analysis ran. Continuation pages reuse the list the first page was
/// counted against, which is what keeps their offsets meaning the same rows.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StringListResult {
    /// Strings in this page.
    pub strings: Vec<StringInfo>,
    /// Total number of matches before pagination, over the whole index — not
    /// over this page. Independent of `limit`.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One extracted string together with the code that references it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StringXrefInfo {
    /// Address of the first byte, hex-formatted.
    pub address: String,
    /// Decoded text.
    pub content: String,
    /// Length in bytes as IDA measured it.
    pub length: usize,
    /// Referencing addresses, hex-formatted, capped by `max_xrefs`.
    pub xrefs: Vec<String>,
    /// Number of entries in `xrefs`.
    pub xref_count: usize,
}

/// Paginated string listing with references.
///
/// Same index-rebuild rule as [`StringListResult`]: `offset: 0` refreshes it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StringXrefsResult {
    /// Strings in this page, each with its references.
    pub strings: Vec<StringXrefInfo>,
    /// Total number of matches before pagination, over the whole index — not
    /// over this page. Independent of `limit`.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// `analyze_strings` output.
///
/// Same rows as [`StringXrefsResult`]. Kept as its own type because the two are
/// assembled differently — this one as raw JSON, that one from a worker struct
/// — and a shared type would hide a divergence rather than prevent one.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeStringsResult {
    /// Strings in this page, each with up to 64 referencing addresses.
    pub strings: Vec<StringXrefInfo>,
    /// Total number of matches before pagination, over the whole index — not
    /// over this page. Independent of `limit`.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One pattern's hits within a `find_bytes` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindBytesEntry {
    /// The pattern exactly as supplied.
    pub pattern: String,
    /// Matching addresses in this page, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<String>>,
    /// How many addresses the bounded scan found; absent on failure.
    ///
    /// A *lower bound* when `total_is_lower_bound` is true — the scan stopped
    /// at its ceiling, not at the end of the database. Never a function of
    /// `limit`: the scan always runs one hit past the requested page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// True when the scan hit its ceiling, so more matches may exist beyond
    /// `total`. Absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_is_lower_bound: Option<bool>,
    /// Offset to pass on the next call; absent on the last page and on failure.
    ///
    /// Absent together with `total_is_lower_bound: true` means the scan ceiling
    /// was reached: there may be more matches, but this call cannot page into
    /// them. Narrow the query instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Why this pattern could not be scanned; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `find_bytes` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindBytesOutput {
    /// One entry per pattern, in the order supplied.
    pub results: Vec<FindBytesEntry>,
}

/// One target's hits within a `search` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchEntry {
    /// The target exactly as supplied.
    pub target: String,
    /// Matching addresses in this page, hex-formatted; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<String>>,
    /// How many addresses the bounded scan found; absent on failure.
    ///
    /// A *lower bound* when `total_is_lower_bound` is true — the scan stopped
    /// at its ceiling, not at the end of the database. Never a function of
    /// `limit`: the scan always runs one hit past the requested page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// True when the scan hit its ceiling, so more matches may exist beyond
    /// `total`. Absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_is_lower_bound: Option<bool>,
    /// Offset to pass on the next call; absent on the last page and on failure.
    ///
    /// Absent together with `total_is_lower_bound: true` means the scan ceiling
    /// was reached: there may be more matches, but this call cannot page into
    /// them. Narrow the query instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Why this target could not be searched; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `search` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchOutput {
    /// One entry per target, in the order supplied.
    pub results: Vec<SearchEntry>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One instruction matched by `find_insns`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsnMatch {
    /// Address of the first instruction of the match, hex-formatted.
    pub address: String,
    /// Mnemonic at `address`.
    pub mnemonic: String,
    /// The disassembly line at `address`, comment stripped.
    pub line: String,
    /// Addresses of every instruction in the sequence, hex-formatted. Present
    /// only when more than one pattern was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<Vec<String>>,
}

/// `find_insns` output.
///
/// # Two ways this answer can be incomplete
///
/// `truncated` says `limit` stopped the scan — there were more matches and they
/// were not looked for. `scan_truncated` says `max_scan` stopped it: the walk
/// gave up before reaching the end of the scope, so matches may exist in the
/// part never decoded. They are independent, and neither is implied by `count`,
/// which is only the length of `matches` — a full page and a complete answer are
/// the same number.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsnSearchOutput {
    /// The patterns exactly as supplied.
    pub patterns: Vec<String>,
    /// Whether matching ignored case.
    pub case_insensitive: bool,
    /// Whether the patterns were treated as regular expressions.
    pub regex: bool,
    /// What was scanned: `database`, `function:0x…`, `segment:…` or a range.
    pub scope: String,
    /// How many instruction heads the walk decoded.
    pub scanned: usize,
    /// Whether the walk stopped at `max_scan` rather than at the end of `scope`.
    pub scan_truncated: bool,
    /// Matches found, capped by `limit`.
    pub matches: Vec<InsnMatch>,
    /// Number of entries in `matches`.
    pub count: usize,
    /// Whether `limit` cut the search short, so more matches may exist.
    pub truncated: bool,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One instruction matched by `find_insn_operands`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsnOperandMatch {
    /// Address of the instruction, hex-formatted.
    pub address: String,
    /// Mnemonic at `address`.
    pub mnemonic: String,
    /// Operand text that matched, comment stripped.
    pub operands: String,
    /// The whole disassembly line at `address`, comment stripped.
    pub line: String,
}

/// `find_insn_operands` output.
///
/// Incomplete in the same two independent ways [`InsnSearchOutput`] is.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsnOperandSearchOutput {
    /// The patterns exactly as supplied.
    pub patterns: Vec<String>,
    /// Whether matching ignored case.
    pub case_insensitive: bool,
    /// Whether the patterns were treated as regular expressions.
    pub regex: bool,
    /// What was scanned: `database`, `function:0x…`, `segment:…` or a range.
    pub scope: String,
    /// How many instruction heads the walk decoded.
    pub scanned: usize,
    /// Whether the walk stopped at `max_scan` rather than at the end of `scope`.
    pub scan_truncated: bool,
    /// Matches found, capped by `limit`.
    pub matches: Vec<InsnOperandMatch>,
    /// Number of entries in `matches`.
    pub count: usize,
    /// Whether `limit` cut the search short, so more matches may exist.
    pub truncated: bool,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}
