//! Function-related handlers.

use crate::error::ToolError;
use crate::ida::handlers::parse_address_str;
use crate::ida::observability::{
    emit_progress, ensure_not_cancelled, ProgressHeartbeat, ProgressSender,
    SINGLE_PHASE_PROGRESS_TOTAL,
};
use crate::ida::query::{FunctionQuery, FunctionSort};
use crate::ida::types::{FunctionInfo, FunctionListResult, FunctionRangeInfo};
use idalib::IDB;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use vibrev_kit::page;

/// Order `functions` in place by the query's sort key.
fn sort_functions(functions: &mut [FunctionInfo], sort_by: FunctionSort, descending: bool) {
    match sort_by {
        // Addresses are formatted hex strings by this point, and "0x9" sorts
        // after "0x10" as text. Parse back rather than compare the rendering.
        FunctionSort::Address => functions.sort_by_key(|f| {
            u64::from_str_radix(f.address.trim_start_matches("0x"), 16).unwrap_or(0)
        }),
        FunctionSort::Name => functions.sort_by(|a, b| a.name.cmp(&b.name)),
        FunctionSort::Size => functions.sort_by_key(|f| f.size),
    }
    if descending {
        functions.reverse();
    }
}

pub fn handle_list_functions(
    idb: &Option<IDB>,
    query: &FunctionQuery,
) -> Result<FunctionListResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let name_filter = query.name_filter()?;
    let full_scan = query.needs_full_scan();

    let mut functions = Vec::with_capacity(query.limit.min(1024));
    let mut total = 0usize;

    for (_id, func) in db.functions() {
        let addr = func.start_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{addr:x}"));
        let size = func.len();

        if !name_filter.matches(&name) || !query.size_matches(size) {
            continue;
        }

        total += 1;
        // A sorted answer cannot be paged during the walk: the page depends on
        // an order that is not known until every match is in hand.
        if !full_scan && (total <= query.offset || functions.len() >= query.limit) {
            continue;
        }

        functions.push(FunctionInfo {
            address: format!("{addr:#x}"),
            name,
            size,
        });
    }

    if let Some(sort_by) = query.sort_by {
        sort_functions(&mut functions, sort_by, query.descending);
        let start = query.offset.min(functions.len());
        let end = start.saturating_add(query.limit).min(functions.len());
        functions = functions[start..end].to_vec();
    }

    let next_offset = page::next_offset(query.offset, functions.len(), total);

    Ok(FunctionListResult {
        functions,
        total,
        next_offset,
    })
}

pub fn handle_resolve_function(idb: &Option<IDB>, name: &str) -> Result<FunctionInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    for (_id, func) in db.functions() {
        if let Some(func_name) = func.name()
            && (func_name == name || func_name.contains(name))
        {
            let addr = func.start_address();
            let size = func.len();
            return Ok(FunctionInfo {
                address: format!("{:#x}", addr),
                name: func_name,
                size,
            });
        }
    }

    Err(ToolError::FunctionNameNotFound(name.to_string()))
}

pub fn handle_lookup_funcs(idb: &Option<IDB>, queries: &[String]) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut results = Vec::with_capacity(queries.len());

    // Precompute functions for name lookups
    let funcs: Vec<FunctionInfo> = db
        .functions()
        .map(|(_id, func)| {
            let addr = func.start_address();
            let name = func.name().unwrap_or_else(|| format!("sub_{:x}", addr));
            let size = func.len();
            FunctionInfo {
                address: format!("{:#x}", addr),
                name,
                size,
            }
        })
        .collect();

    for query in queries {
        if let Ok(addr) = parse_address_str(query) {
            if let Some(func) = db.function_at(addr) {
                let info = FunctionInfo {
                    address: format!("{:#x}", func.start_address()),
                    name: func
                        .name()
                        .unwrap_or_else(|| format!("sub_{:x}", func.start_address())),
                    size: func.len(),
                };
                results.push(json!({"query": query, "result": info}));
            } else {
                results.push(json!({"query": query, "error": "Function not found"}));
            }
            continue;
        }

        if let Some(info) = funcs
            .iter()
            .find(|f| f.name == *query || f.name.contains(query))
        {
            results.push(json!({"query": query, "result": info}));
        } else {
            results.push(json!({"query": query, "error": "Function not found"}));
        }
    }

    Ok(json!({ "results": results }))
}

pub fn handle_analyze_funcs(
    idb: &mut Option<IDB>,
    progress_tx: Option<ProgressSender>,
    cancel: Option<CancellationToken>,
) -> Result<Value, ToolError> {
    let db = idb.as_mut().ok_or(ToolError::NoDatabaseOpen)?;
    ensure_not_cancelled(cancel.as_ref())?;
    let _heartbeat = ProgressHeartbeat::start(
        progress_tx.clone(),
        "analyzing",
        0.0,
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "Waiting for IDA auto-analysis to finish",
    );
    let completed = db.auto_wait();
    ensure_not_cancelled(cancel.as_ref())?;
    emit_progress(
        progress_tx.as_ref(),
        "analyzing",
        0.95,
        Some(SINGLE_PHASE_PROGRESS_TOTAL),
        "IDA auto-analysis finished; collecting result",
    );
    Ok(json!({
        "completed": completed,
        "function_count": db.function_count(),
    }))
}

pub fn handle_function_at(idb: &Option<IDB>, addr: u64) -> Result<FunctionRangeInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let func = db
        .function_at(addr)
        .ok_or(ToolError::FunctionNotFound(addr))?;
    let start = func.start_address();
    let end = func.end_address();
    let name = func.name().unwrap_or_else(|| format!("sub_{:x}", start));
    Ok(FunctionRangeInfo {
        address: format!("{:#x}", start),
        name,
        start: format!("{:#x}", start),
        end: format!("{:#x}", end),
        size: func.len(),
    })
}
