//! Function listing and lookup output types.

use crate::ida::types as worker;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;

/// One function in a listing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionInfo {
    /// Entry address, hex-formatted (`0x1400010a0`).
    pub address: String,
    /// Symbol name, demangled when IDA has a demangler for it.
    pub name: String,
    /// Size in bytes of the function's primary chunk.
    pub size: usize,
}

impl From<&worker::FunctionInfo> for FunctionInfo {
    fn from(function: &worker::FunctionInfo) -> Self {
        Self {
            address: function.address.clone(),
            name: function.name.clone(),
            size: function.size,
        }
    }
}

/// Paginated function listing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionListResult {
    /// Functions in this page.
    pub functions: Vec<FunctionInfo>,
    /// Total number of functions matching the request, before pagination.
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

/// One answer of a batch function lookup.
///
/// `result` and `error` are mutually exclusive: a query that resolved carries
/// the function, one that did not carries the reason.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupFuncEntry {
    /// The query exactly as supplied — an address or a name.
    pub query: String,
    /// The function it resolved to; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<FunctionInfo>,
    /// Why the query did not resolve; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `lookup_funcs` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LookupFuncsOutput {
    /// One entry per query, in the order supplied.
    pub results: Vec<LookupFuncEntry>,
}

/// `export_funcs` output.
///
/// Without `addrs` it exports a page of the function list
/// (`functions`/`total`/`next_offset`); with `addrs` it resolves each one and
/// answers like `lookup_funcs` (`results`).
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportFuncsOutput {
    /// Functions in this page; absent when `addrs` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<FunctionInfo>>,
    /// Total functions before pagination; absent when `addrs` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// One entry per requested address; absent when `addrs` was not given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<LookupFuncEntry>>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// Address range of the function containing an address.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionRangeInfo {
    /// The address that was queried, hex-formatted.
    pub address: String,
    /// Name of the containing function.
    pub name: String,
    /// First address of the function, hex-formatted.
    pub start: String,
    /// One past the last address of the function, hex-formatted.
    pub end: String,
    /// `end - start`, in bytes.
    pub size: usize,
}
