//! Cross-reference listing and matrix output types.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;

/// One cross-reference.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XRefInfo {
    /// Referencing address, hex-formatted.
    pub from: String,
    /// Referenced address, hex-formatted.
    pub to: String,
    /// IDA's reference type name (`Call_Near`, `Data_Offset`, ...).
    pub r#type: String,
    /// True for a code reference, false for a data reference.
    pub is_code: bool,
    /// The function the reference comes from. Present only when the call
    /// passed `include_function`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<FunctionRef>,
}

/// A function named by address, embedded in another answer.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionRef {
    /// Function entry point, hex-formatted.
    pub address: String,
    /// Function name.
    pub name: String,
}

/// One page of cross-references.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XRefListResult {
    /// References in this page.
    pub xrefs: Vec<XRefInfo>,
    /// True when more references exist past this page.
    pub truncated: bool,
    /// Offset to pass on the next call; absent when `truncated` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

/// One page of cross-references, tagged with the address it belongs to.
///
/// Emitted per address when several addresses were requested at once; the
/// error arm replaces the payload with a message.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XRefBatchEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// References found at `address`; absent when the lookup failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<Vec<XRefInfo>>,
    /// True when more references exist past this page; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// Offset to pass on the next call for this address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Why this address could not be answered; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `xrefs_to` / `xrefs_from` output.
///
/// One requested address produces the flat listing (`xrefs`/`truncated`);
/// several produce `results`, one entry per address.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XRefsOutput {
    /// References for the single requested address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<Vec<XRefInfo>>,
    /// True when more references exist past this page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// Offset to pass on the next call; absent when `truncated` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// One entry per address when several addresses were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<XRefBatchEntry>>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// References to one field of a structure.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefsToFieldResult {
    /// Ordinal of the owning structure.
    pub struct_ordinal: u32,
    /// Name of the owning structure.
    pub struct_name: String,
    /// Zero-based index of the member within the structure.
    pub member_index: u32,
    /// Member name.
    pub member_name: String,
    /// C type of the member.
    pub member_type: String,
    /// Member offset within the structure, in bits.
    pub member_offset_bits: u64,
    /// Member width in bits.
    pub member_size_bits: u64,
    /// IDA type id of the member, hex-formatted.
    pub tid: String,
    /// References to the member.
    pub xrefs: Vec<XRefInfo>,
    /// True when more references exist past `limit`.
    pub truncated: bool,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// `xref_matrix` output.
///
/// `matrix[i][j]` is true when `addrs[i]` references `addrs[j]`. Square, in
/// the order the addresses were requested, and always fully populated.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XrefMatrixOutput {
    /// The requested addresses, hex-formatted, in request order.
    pub addrs: Vec<String>,
    /// Row per address, column per address; true means "row references column".
    pub matrix: Vec<Vec<bool>>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}
