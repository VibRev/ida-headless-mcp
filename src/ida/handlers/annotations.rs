//! Comment and rename handlers.

use crate::error::ToolError;
use crate::ida::handlers::resolve_address;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_add_bookmark(
    idb: &Option<IDB>,
    addr: u64,
    description: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let bookmarks = db.bookmarks();
    let slot = if let Some(slot) = bookmarks.find_index(addr) {
        bookmarks.erase_by_index(slot)?;
        bookmarks.mark_with(addr, slot, description)?
    } else {
        bookmarks.mark(addr, description)?
    };
    Ok(json!({
        "address": format!("{addr:#x}"),
        "slot": slot,
        "description": description,
    }))
}

pub fn handle_set_comments(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    comment: &str,
    repeatable: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    if repeatable {
        db.set_cmt_with(addr, comment, true)?;
    } else {
        db.set_cmt(addr, comment)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "repeatable": repeatable,
        "comment": comment,
    }))
}

pub fn handle_append_comment(
    idb: &Option<IDB>,
    addr: u64,
    comment: &str,
    scope: &str,
    dedupe: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let function = db.function_at(addr);
    let use_function = match scope {
        "func" => true,
        "line" => false,
        "auto" => function
            .as_ref()
            .is_some_and(|function| function.start_address() == addr),
        _ => {
            return Err(ToolError::InvalidParams(format!(
                "unsupported comment scope: {scope}"
            )));
        }
    };
    let (target, current) = if use_function {
        let function = function.ok_or(ToolError::FunctionNotFound(addr))?;
        let target = function.start_address();
        (target, db.get_func_cmt(target).unwrap_or_default())
    } else {
        (addr, db.get_cmt(addr).unwrap_or_default())
    };
    let normalized = comment.trim();
    if dedupe && !normalized.is_empty() && current.lines().any(|line| line.trim() == normalized) {
        return Ok(json!({
            "address": format!("{addr:#x}"),
            "scope": if use_function { "func" } else { "line" },
            "skipped": true,
        }));
    }
    let combined = if current.is_empty() || comment.is_empty() || current.ends_with('\n') {
        format!("{current}{comment}")
    } else {
        format!("{current}\n{comment}")
    };
    if use_function {
        db.set_func_cmt(target, combined)?;
    } else {
        db.set_cmt(target, combined)?;
    }
    Ok(json!({
        "address": format!("{addr:#x}"),
        "scope": if use_function { "func" } else { "line" },
        "appended": true,
    }))
}

pub fn handle_rename(
    idb: &Option<IDB>,
    addr: Option<u64>,
    current_name: Option<&str>,
    name: &str,
    flags: i32,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, current_name, 0)?;
    if flags == 0 {
        db.set_name(addr, name)?;
    } else {
        db.set_name_with_flags(addr, name, flags)?;
    }
    Ok(json!({
        "address": format!("{:#x}", addr),
        "name": name,
        "flags": flags,
    }))
}
