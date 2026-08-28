//! String-related handlers.

use crate::error::ToolError;
use crate::ida::handlers::hex_encode;
use crate::ida::query::{StringQuery, StringSearch, StringSort};
use crate::ida::types::{StringInfo, StringListResult, StringXrefInfo, StringXrefsResult};
use idalib::xref::XRefQuery;
use idalib::IDB;
use serde_json::{json, Value};
use vibrev_kit::page;

/// Should this call rebuild IDA's string index before scanning it?
///
/// Only when the scan starts from the beginning. Continuation pages
/// deliberately reuse the list their first page was counted against: paging is
/// by position, so rebuilding mid-sequence would renumber the very offsets the
/// caller was handed. It also means a caller paging through a large database
/// pays for one rebuild, not one per page.
fn should_rebuild_string_index(offset: usize) -> bool {
    offset == 0
}

/// Bring IDA's string index up to date before a fresh scan.
///
/// `db.strings()` is a view over `get_strlist_qty()` and friends — an index IDA
/// builds *once*, while loading, before auto-analysis has decided which byte
/// runs are code. Nothing rebuilds it afterwards, so without this call every
/// string tool answers out of the loader's guess for the rest of the session.
/// Measured on a stock `/bin/cat` opened with `run_auto_analysis: false`:
/// `strings` reports 226 before analysis and still 226 after `analyze_funcs`
/// has settled, where a rebuild says 194.
///
/// That is worse than an incomplete answer, because the stale count arrives
/// next to `analysis_coverage.complete = true` and is therefore indistinguish-
/// able from a settled one. The coverage marker cannot catch it: analysis
/// really has finished; the index just predates it.
///
/// The rebuild is what IDA's own Strings window does. Cost is one pass over the
/// defined string items — 1-3 ms on `/bin/cat`, 32 ms on a 1.2 MB `/bin/bash`
/// with 3816 strings.
/// Rebuild IDA's string index on an already-open database.
///
/// Same work `refresh_string_index` does for a fresh scan (`offset == 0`).
/// Open-time warmup calls this so the first `strings` page is not the first
/// rebuild of the session.
pub fn rebuild_string_index(db: &IDB) {
    db.strings().rebuild();
}

fn refresh_string_index(db: &IDB, offset: usize) {
    if should_rebuild_string_index(offset) {
        rebuild_string_index(db);
    }
}

pub fn handle_strings(
    idb: &Option<IDB>,
    query: &StringQuery,
) -> Result<StringListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let name_filter = query.name_filter()?;
    let full_scan = query.needs_full_scan();

    refresh_string_index(db, query.offset);
    let string_list = db.strings();
    let mut total = 0usize;
    let mut strings = Vec::new();

    for (addr, content) in string_list.iter() {
        if !name_filter.matches(&content) || !query.length_matches(content.len()) {
            continue;
        }

        total += 1;
        // See `handle_list_functions`: a sorted page is not knowable mid-walk.
        if !full_scan && (total <= query.offset || strings.len() >= query.limit) {
            continue;
        }

        strings.push(StringInfo {
            address: format!("{addr:#x}"),
            content: content.clone(),
            length: content.len(),
        });
    }

    if let Some(sort_by) = query.sort_by {
        sort_strings(&mut strings, sort_by, query.descending);
        let start = query.offset.min(strings.len());
        let end = start.saturating_add(query.limit).min(strings.len());
        strings = strings[start..end].to_vec();
    }

    let next_offset = page::next_offset(query.offset, strings.len(), total);

    Ok(StringListResult {
        strings,
        total,
        next_offset,
    })
}

/// Order `strings` in place by the query's sort key.
fn sort_strings(strings: &mut [StringInfo], sort_by: StringSort, descending: bool) {
    match sort_by {
        // Rendered hex sorts as text; parse it back so 0x9 precedes 0x10.
        StringSort::Address => strings.sort_by_key(|s| {
            u64::from_str_radix(s.address.trim_start_matches("0x"), 16).unwrap_or(0)
        }),
        StringSort::Length => strings.sort_by_key(|s| s.length),
        StringSort::Content => strings.sort_by(|a, b| a.content.cmp(&b.content)),
    }
    if descending {
        strings.reverse();
    }
}

pub fn handle_analyze_strings(idb: &Option<IDB>, query: &StringQuery) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let name_filter = query.name_filter()?;

    refresh_string_index(db, query.offset);
    let string_list = db.strings();
    let mut total = 0usize;
    let mut results = Vec::new();

    for (addr, content) in string_list.iter() {
        if !name_filter.matches(&content) || !query.length_matches(content.len()) {
            continue;
        }

        total += 1;
        if total <= query.offset || results.len() >= query.limit {
            continue;
        }

        let mut xrefs = Vec::new();
        let mut current = db.first_xref_to(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            xrefs.push(format!("{:#x}", xref.from()));
            if xrefs.len() >= 64 {
                break;
            }
            current = xref.next_to();
        }

        results.push(json!({
            "address": format!("{:#x}", addr),
            "content": content,
            "length": content.len(),
            "xrefs": xrefs,
            "xref_count": xrefs.len(),
        }));
    }

    let next_offset = page::next_offset(query.offset, results.len(), total);

    // `next_offset` is omitted rather than null on the last page, matching the
    // struct-serialized listings; see `crate::server::responses`.
    let mut out = json!({
        "strings": results,
        "total": total,
    });
    if let Some(next) = next_offset {
        out["next_offset"] = json!(next);
    }
    Ok(out)
}

pub fn handle_get_string(idb: &Option<IDB>, addr: u64, max_len: usize) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let max_len = max_len.min(0x10000);
    let bytes = db.get_bytes(addr, max_len);
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..len]).into_owned();

    Ok(json!({
        "address": format!("{:#x}", addr),
        "string": s,
        "length": len,
        "bytes": hex_encode(&bytes[..len]),
    }))
}

pub fn handle_find_string(
    idb: &Option<IDB>,
    search: &StringSearch,
) -> Result<StringListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let matcher = search.matcher()?;

    refresh_string_index(db, search.offset);
    let mut total = 0usize;
    let mut strings = Vec::new();

    for (addr, content) in db.strings().iter() {
        if !matcher.matches(&content, &search.fold(&content)) {
            continue;
        }

        total += 1;
        if total <= search.offset {
            continue;
        }
        if strings.len() >= search.limit {
            continue;
        }

        strings.push(StringInfo {
            address: format!("{:#x}", addr),
            content: content.clone(),
            length: content.len(),
        });
    }

    let next_offset = page::next_offset(search.offset, strings.len(), total);

    Ok(StringListResult {
        strings,
        total,
        next_offset,
    })
}

pub fn handle_xrefs_to_string(
    idb: &Option<IDB>,
    search: &StringSearch,
    max_xrefs: usize,
) -> Result<StringXrefsResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let matcher = search.matcher()?;

    refresh_string_index(db, search.offset);
    let mut total = 0usize;
    let mut strings = Vec::new();
    let max_xrefs = max_xrefs.clamp(1, 1024);

    for (addr, content) in db.strings().iter() {
        if !matcher.matches(&content, &search.fold(&content)) {
            continue;
        }

        total += 1;
        if total <= search.offset {
            continue;
        }
        if strings.len() >= search.limit {
            continue;
        }

        let mut xrefs = Vec::new();
        let mut current = db.first_xref_to(addr, XRefQuery::ALL);
        while let Some(xref) = current {
            xrefs.push(format!("{:#x}", xref.from()));
            if xrefs.len() >= max_xrefs {
                break;
            }
            current = xref.next_to();
        }

        let xref_count = xrefs.len();
        strings.push(StringXrefInfo {
            address: format!("{:#x}", addr),
            content: content.clone(),
            length: content.len(),
            xrefs,
            xref_count,
        });
    }

    let next_offset = page::next_offset(search.offset, strings.len(), total);

    Ok(StringXrefsResult {
        strings,
        total,
        next_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::should_rebuild_string_index;

    #[test]
    fn only_a_scan_that_starts_at_zero_rebuilds_the_index() {
        assert!(should_rebuild_string_index(0));
        // A continuation page must see the same list its offsets were minted
        // against, or paging silently skips and repeats rows.
        assert!(!should_rebuild_string_index(1));
        assert!(!should_rebuild_string_index(5000));
    }
}
