//! Wire-value parsers that are not address-specific.

use crate::error::ToolError;

/// Convert an optional i64 wire field into an unsigned Rust type used by the
/// worker.
///
/// The conversion itself is `vibrev_kit`'s. The `i64` on the wire is that
/// crate's rule — a published input schema may not carry a `uint*`, which is
/// what `contract::Rule::UnportableFormat` scans for — and an engine that
/// invents its own way back from it is how the rule and the reading of it drift
/// apart. What stays here is this repository's error type, so the 96 call sites
/// keep answering with `InvalidParams` and nothing else has to move.
pub(crate) fn parse_optional_unsigned<T>(
    value: Option<i64>,
    name: &str,
) -> Result<Option<T>, ToolError>
where
    T: TryFrom<i64>,
{
    vibrev_kit::parse_optional_unsigned(value, name)
        .map_err(|out_of_range| ToolError::InvalidParams(out_of_range.to_string()))
}

/// Resolve a listing's `offset` / `limit` pair into the numbers it counts in.
///
/// Same division of labour as above: the arithmetic is kit's, the error type is
/// this repository's.
///
/// The seven listings that call this need a lower bound as much as an upper one:
/// a `limit` of zero yields an empty page whose `next_offset` cannot advance, so
/// a client paging with it receives nothing and is told nothing is left.
/// `page::bounds` clamps into `1..=max`.
pub(crate) fn page_bounds(
    offset: Option<i64>,
    limit: Option<i64>,
    default: usize,
    max: usize,
) -> Result<(usize, usize), ToolError> {
    vibrev_kit::page::bounds(offset, limit, default, max)
        .map_err(|out_of_range| ToolError::InvalidParams(out_of_range.to_string()))
}
