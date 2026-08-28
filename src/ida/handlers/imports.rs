//! Import, export, and entrypoint handlers.

use crate::error::ToolError;
use crate::ida::query::NameQuery;
use crate::ida::types::{ExportInfo, ExportListResult, ImportInfo, ImportListResult};
use idalib::IDB;
use std::collections::HashSet;
use vibrev_kit::page::Page;

pub fn handle_imports(idb: &Option<IDB>, query: &NameQuery) -> Result<ImportListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let name_filter = query.name_filter()?;
    let full_scan = query.needs_full_scan();

    let mut imports = Vec::new();
    let mut count = 0usize;

    for name in db.names().iter() {
        // Imports are names in external segments.
        let Some(seg) = db.segment_at(name.address()) else {
            continue;
        };
        if !(seg.r#type().is_extern() || seg.r#type().is_import()) {
            continue;
        }
        let module = seg.name().unwrap_or_default();
        if !name_filter.matches(name.name()) || !query.module_matches(&module) {
            continue;
        }

        // `ordinal` counts matches, so a filtered listing numbers its own
        // answer rather than leaving gaps where filtered-out names were.
        let ordinal = count;
        count += 1;
        if !full_scan && (ordinal < query.offset || imports.len() >= query.limit) {
            continue;
        }

        imports.push(ImportInfo {
            address: format!("{:#x}", name.address()),
            name: name.name().to_string(),
            module,
            ordinal,
        });
    }

    query.sort(&mut imports, |i| &i.address, |i| &i.name);
    // `count` is the match total, not the page size, and it has to reach the
    // response: without it a caller holding a hundred imports cannot tell a
    // hundred from ten thousand.
    let page = Page::counted(imports, query.offset, count);
    Ok(ImportListResult {
        imports: page.items,
        total: page.total,
        next_offset: page.next_offset,
    })
}

pub fn handle_exports(idb: &Option<IDB>, query: &NameQuery) -> Result<ExportListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let name_filter = query.name_filter()?;
    let full_scan = query.needs_full_scan();

    let mut exports = Vec::new();
    let mut count = 0usize;

    for name in db.names().iter() {
        if !name_filter.matches(name.name()) {
            continue;
        }

        let index = count;
        count += 1;
        if !full_scan && (index < query.offset || exports.len() >= query.limit) {
            continue;
        }

        exports.push(ExportInfo {
            address: format!("{:#x}", name.address()),
            name: name.name().to_string(),
            is_public: name.is_public(),
        });
    }

    query.sort(&mut exports, |e| &e.address, |e| &e.name);
    let page = Page::counted(exports, query.offset, count);
    Ok(ExportListResult {
        exports: page.items,
        total: page.total,
        next_offset: page.next_offset,
    })
}

pub fn handle_entrypoints(idb: &Option<IDB>) -> Result<Vec<String>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    // idalib's EntryPointIter has a bug: index is not incremented on success,
    // causing infinite iteration. Break as soon as a duplicate address is seen.
    let mut seen = HashSet::new();
    let mut entrypoints = Vec::new();
    for addr in db.entries() {
        if !seen.insert(addr) {
            break;
        }
        entrypoints.push(format!("{:#x}", addr));
    }

    Ok(entrypoints)
}
