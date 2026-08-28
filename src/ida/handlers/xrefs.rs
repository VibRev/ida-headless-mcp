//! Cross-reference handlers.

use crate::error::ToolError;
use crate::ida::query::XrefQuery as XrefQuerySpec;
use crate::ida::types::{FunctionRef, XRefInfo, XRefListResult};
use idalib::xref::{XRef, XRefQuery};
use idalib::IDB;
use serde_json::{json, Value};
use std::collections::HashSet;
use vibrev_kit::page;

fn to_xref_info(xref: &XRef) -> XRefInfo {
    XRefInfo {
        from: format!("{:#x}", xref.from()),
        to: format!("{:#x}", xref.to()),
        r#type: format!("{:?}", xref.type_()),
        is_code: xref.is_code(),
        from_function: None,
    }
}

/// What to do with an item that passed filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Before the requested page.
    Skip,
    /// Inside the page: collect it.
    Take,
    /// Past the page: stop walking, and report truncation.
    Stop,
}

/// Tracks where a filtered walk sits relative to the requested page.
///
/// Traversal stops one item past the page rather than running the chain to its
/// end, so a high-frequency target cannot peg the worker thread.
struct PageCursor {
    offset: usize,
    limit: usize,
    kept: usize,
    taken: usize,
}

impl PageCursor {
    fn new(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            kept: 0,
            taken: 0,
        }
    }

    /// Admit one item that already passed filtering, advancing the cursor.
    fn admit(&mut self) -> Admit {
        if self.kept < self.offset {
            self.kept += 1;
            return Admit::Skip;
        }
        if self.taken == self.limit {
            return Admit::Stop;
        }
        self.kept += 1;
        self.taken += 1;
        Admit::Take
    }
}

/// Walk an xref chain applying kind filtering, dedup and function lookup,
/// then take the requested page.
///
/// Filtering has to happen *before* paging: an `offset` counted over the
/// unfiltered chain would skip a different set of references than the one the
/// caller is paging through.
fn collect_query<'a>(
    db: &IDB,
    first: Option<XRef<'a>>,
    query: &XrefQuerySpec,
    mut advance: impl FnMut(&XRef<'a>) -> Option<XRef<'a>>,
) -> XRefListResult {
    let mut seen = HashSet::new();
    let mut xrefs = Vec::new();
    let mut cursor = PageCursor::new(query.offset, query.limit);
    let mut truncated = false;
    let mut current = first;

    while let Some(xref) = current {
        let keep = query.kind.keeps(xref.is_code())
            && (!query.dedup
                || seen.insert((xref.from(), xref.to(), format!("{:?}", xref.type_()))));

        if keep {
            match cursor.admit() {
                Admit::Skip => {}
                Admit::Take => {
                    let mut info = to_xref_info(&xref);
                    if query.include_function {
                        info.from_function = enclosing_function(db, xref.from());
                    }
                    xrefs.push(info);
                }
                Admit::Stop => {
                    truncated = true;
                    break;
                }
            }
        }

        current = advance(&xref);
    }

    // A bounded scan has no total: it stopped when it had `limit` hits and never
    // counted what lay past them. `truncated` says there is at least one more,
    // which is all the comparison needs — and routing it through the shared
    // definition is what stops an empty-but-truncated page from handing back the
    // offset it was given, which a client would follow forever.
    let at_least = query
        .offset
        .saturating_add(xrefs.len())
        .saturating_add(usize::from(truncated));
    let next_offset = page::next_offset(query.offset, xrefs.len(), at_least);
    XRefListResult {
        xrefs,
        truncated,
        next_offset,
    }
}

/// The function containing `addr`, if any.
fn enclosing_function(db: &IDB, addr: u64) -> Option<FunctionRef> {
    db.function_at(addr).map(|func| {
        let start = func.start_address();
        FunctionRef {
            address: format!("{start:#x}"),
            name: func.name().unwrap_or_else(|| format!("sub_{start:x}")),
        }
    })
}

pub fn handle_xrefs_to(
    idb: &Option<IDB>,
    addr: u64,
    query: &XrefQuerySpec,
) -> Result<XRefListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Ok(collect_query(
        db,
        db.first_xref_to(addr, XRefQuery::ALL),
        query,
        |xref| xref.next_to(),
    ))
}

pub fn handle_xrefs_from(
    idb: &Option<IDB>,
    addr: u64,
    query: &XrefQuerySpec,
) -> Result<XRefListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Ok(collect_query(
        db,
        db.first_xref_from(addr, XRefQuery::ALL),
        query,
        |xref| xref.next_from(),
    ))
}

pub fn handle_xref_matrix(idb: &Option<IDB>, addrs: &[u64]) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let mut xref_map: std::collections::HashMap<u64, HashSet<u64>> =
        std::collections::HashMap::new();

    for &addr in addrs {
        let mut set = HashSet::new();
        let mut current = db.first_xref_from(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            set.insert(xref.to());
            current = xref.next_from();
        }
        xref_map.insert(addr, set);
    }

    let matrix: Vec<Vec<bool>> = addrs
        .iter()
        .map(|from| {
            addrs
                .iter()
                .map(|to| xref_map.get(from).map(|s| s.contains(to)).unwrap_or(false))
                .collect()
        })
        .collect();

    Ok(json!({
        "addrs": addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>(),
        "matrix": matrix
    }))
}

#[cfg(test)]
mod tests {
    use crate::ida::handlers::xrefs::{Admit, PageCursor};

    /// Drive a cursor over the chain `0, 1, .., len - 1`, the way
    /// `collect_query` drives it over an xref chain that passed filtering.
    fn window_of(len: usize, offset: usize, limit: usize) -> (Vec<usize>, bool) {
        let mut cursor = PageCursor::new(offset, limit);
        let mut items = Vec::new();
        for i in 0..len {
            match cursor.admit() {
                Admit::Skip => {}
                Admit::Take => items.push(i),
                Admit::Stop => return (items, true),
            }
        }
        (items, false)
    }

    #[test]
    fn window_within_available_is_not_truncated() {
        let (items, truncated) = window_of(3, 0, 10);
        assert_eq!(items, vec![0, 1, 2]);
        assert!(!truncated);
    }

    #[test]
    fn window_exactly_full_is_not_truncated() {
        // Exactly `limit` items remain after `offset`: full page, nothing beyond.
        let (items, truncated) = window_of(5, 0, 5);
        assert_eq!(items, vec![0, 1, 2, 3, 4]);
        assert!(!truncated);
    }

    #[test]
    fn window_with_more_available_is_truncated() {
        let (items, truncated) = window_of(100, 0, 5);
        assert_eq!(items, vec![0, 1, 2, 3, 4]);
        assert!(truncated);
    }

    #[test]
    fn offset_skips_leading_items() {
        let (items, truncated) = window_of(10, 3, 4);
        assert_eq!(items, vec![3, 4, 5, 6]);
        assert!(truncated);
    }

    #[test]
    fn offset_past_end_yields_empty() {
        let (items, truncated) = window_of(3, 10, 5);
        assert!(items.is_empty());
        assert!(!truncated);
    }

    #[test]
    fn zero_limit_reports_truncation_without_collecting() {
        let (items, truncated) = window_of(3, 0, 0);
        assert!(items.is_empty());
        assert!(truncated);
    }

    #[test]
    fn zero_limit_at_end_is_not_truncated() {
        let (items, truncated) = window_of(3, 3, 0);
        assert!(items.is_empty());
        assert!(!truncated);
    }
}
