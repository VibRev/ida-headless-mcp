//! Address context, segments, and symbol-table output types.

use crate::ida::types as worker;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;
use super::functions::FunctionRangeInfo;

/// Nearest named symbol to an address.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolInfo {
    /// Symbol name.
    pub name: String,
    /// Symbol address, hex-formatted.
    pub address: String,
    /// Signed distance from the queried address to the symbol.
    pub delta: i64,
    /// True when the symbol sits exactly on the queried address.
    pub exact: bool,
    /// True for a public (exported) name.
    pub is_public: bool,
    /// True for a weak name.
    pub is_weak: bool,
}

/// One segment of the address space.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SegmentInfo {
    /// Segment name as IDA reports it (`__text`, `.rdata`, ...).
    pub name: String,
    /// First address, hex-formatted.
    pub start: String,
    /// One past the last address, hex-formatted.
    pub end: String,
    /// `end - start`, in bytes.
    pub size: usize,
    /// Permission triple such as `r-x`; `---` when IDA reports none.
    pub permissions: String,
    /// Segment class (`CODE`, `DATA`, `BSS`, ...).
    pub r#type: String,
    /// Addressing width of the segment: 16, 32 or 64.
    pub bitness: u32,
}

impl From<&worker::SegmentInfo> for SegmentInfo {
    fn from(segment: &worker::SegmentInfo) -> Self {
        Self {
            name: segment.name.clone(),
            start: segment.start.clone(),
            end: segment.end.clone(),
            size: segment.size,
            permissions: segment.permissions.clone(),
            r#type: segment.r#type.clone(),
            bitness: segment.bitness,
        }
    }
}

/// Everything known about one address: where it lives and what names it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressInfo {
    /// The address that was queried, hex-formatted.
    pub address: String,
    /// Segment containing the address; absent when it is unmapped.
    pub segment: Option<SegmentInfo>,
    /// Function containing the address; absent outside any function.
    pub function: Option<FunctionRangeInfo>,
    /// Nearest symbol at or before the address; absent when there is none.
    pub symbol: Option<SymbolInfo>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One imported symbol.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportInfo {
    /// Import thunk/slot address, hex-formatted.
    pub address: String,
    /// Imported symbol name.
    pub name: String,
    /// Library the symbol comes from.
    pub module: String,
    /// Ordinal, or 0 when the import is by name.
    pub ordinal: usize,
}

/// `imports` output.
///
/// An object rather than a bare JSON array of the page, because
/// `analysis_coverage` needs somewhere to live: the import table is drawn from
/// the same name index that auto-analysis writes, and re-reading it after
/// analysis settles changes the module attribution of entries the first read
/// already listed.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportListOutput {
    /// Imports in this page, in database order.
    pub imports: Vec<ImportInfo>,
    /// Total number of matches before pagination.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    pub analysis_coverage: AnalysisCoverage,
}

/// One exported or public name.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportInfo {
    /// Symbol address, hex-formatted.
    pub address: String,
    /// Symbol name.
    pub name: String,
    /// True when IDA marks the name public.
    pub is_public: bool,
}

/// `exports` output.
///
/// An object for the same reason [`ImportListOutput`] is one, and with more at
/// stake: this tool enumerates the entire name list, which grows by every
/// function auto-analysis creates. On a stock `/bin/cat` it answers 251 names
/// before analysis settles and 381 after.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportListOutput {
    /// Names in this page, in database order.
    pub exports: Vec<ExportInfo>,
    /// Total number of matches before pagination.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    pub analysis_coverage: AnalysisCoverage,
}

/// One named address that is not a function.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalInfo {
    /// Symbol address, hex-formatted.
    pub address: String,
    /// Symbol name.
    pub name: String,
    /// True when IDA marks the name public.
    pub is_public: bool,
    /// True for a weak name; absent when the database does not say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_weak: Option<bool>,
}

/// `list_globals` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GlobalListResult {
    /// Globals in this page.
    pub globals: Vec<GlobalInfo>,
    /// Total number of matches before pagination.
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
