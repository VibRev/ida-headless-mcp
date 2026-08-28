//! IDA SDK-backed database mutation handlers.

use crate::error::ToolError;
use crate::ida::sdk_bridge;
use idalib::IDB;
use serde_json::{json, Value};

fn require_database(idb: &Option<IDB>) -> Result<&IDB, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)
}

pub fn handle_idb_save(idb: &Option<IDB>, path: Option<&str>) -> Result<Value, ToolError> {
    require_database(idb)?;
    let saved = sdk_bridge::save_database(path, path.is_some()).map_err(ToolError::IdaError)?;
    if !saved {
        return Err(ToolError::IdaError(
            "save_database returned false".to_string(),
        ));
    }
    Ok(json!({"ok": true, "path": path}))
}

pub fn handle_define_func(
    idb: &Option<IDB>,
    start: u64,
    end: Option<u64>,
) -> Result<Value, ToolError> {
    let db = require_database(idb)?;
    if db
        .function_at(start)
        .is_some_and(|function| function.start_address() == start)
    {
        return Err(ToolError::InvalidParams(format!(
            "function already exists at {start:#x}"
        )));
    }
    if !sdk_bridge::add_func(start, end) {
        return Err(ToolError::IdaError("add_func returned false".to_string()));
    }
    let function = db
        .function_at(start)
        .ok_or_else(|| ToolError::IdaError("created function was not found".to_string()))?;
    Ok(json!({
        "start": format!("{:#x}", function.start_address()),
        "end": format!("{:#x}", function.end_address()),
    }))
}

pub fn handle_define_code(idb: &Option<IDB>, address: u64) -> Result<Value, ToolError> {
    require_database(idb)?;
    let length = sdk_bridge::create_insn(address);
    if length == 0 {
        return Err(ToolError::IdaError("create_insn returned zero".to_string()));
    }
    Ok(json!({
        "address": format!("{address:#x}"),
        "length": length,
    }))
}

pub fn handle_undefine(idb: &Option<IDB>, address: u64, size: u64) -> Result<Value, ToolError> {
    require_database(idb)?;
    if !sdk_bridge::undefine(address, size) {
        return Err(ToolError::IdaError("del_items returned false".to_string()));
    }
    Ok(json!({
        "address": format!("{address:#x}"),
        "size": size,
    }))
}

pub fn handle_reanalyze(idb: &Option<IDB>, start: u64, end: u64) -> Result<Value, ToolError> {
    require_database(idb)?;
    if !sdk_bridge::reanalyze(start, end) {
        return Err(ToolError::IdaError(
            "plan_and_wait returned false".to_string(),
        ));
    }
    Ok(json!({
        "start": format!("{start:#x}"),
        "end": format!("{end:#x}"),
    }))
}

pub fn handle_mark_cfunc_dirty(idb: &Option<IDB>, address: u64) -> Result<Value, ToolError> {
    let db = require_database(idb)?;
    let function = db
        .function_at(address)
        .ok_or(ToolError::FunctionNotFound(address))?;
    let start = function.start_address();
    if !sdk_bridge::mark_cfunc_dirty(start) {
        return Err(ToolError::IdaError(
            "Hex-Rays cache invalidation failed".to_string(),
        ));
    }
    Ok(json!({
        "address": format!("{start:#x}"),
        "name": function.name().unwrap_or_default(),
    }))
}

pub fn handle_enum_upsert_member(
    idb: &Option<IDB>,
    enum_name: &str,
    member_name: &str,
    value: u64,
    bitfield: bool,
) -> Result<Value, ToolError> {
    require_database(idb)?;
    match sdk_bridge::enum_upsert_member(enum_name, member_name, value, bitfield)
        .map_err(ToolError::IdaError)?
    {
        sdk_bridge::EnumMemberUpsert::Created {
            enum_created,
            ordinal,
        } => Ok(json!({
            "enum_created": enum_created,
            "ordinal": ordinal,
            "member_created": true,
            "skipped": false,
        })),
        sdk_bridge::EnumMemberUpsert::Skipped { ordinal } => Ok(json!({
            "enum_created": false,
            "ordinal": ordinal,
            "member_created": false,
            "skipped": true,
        })),
    }
}

pub fn handle_rename_variable(
    idb: &Option<IDB>,
    function_address: u64,
    old_name: &str,
    new_name: &str,
    stack: bool,
) -> Result<Value, ToolError> {
    require_database(idb)?;
    let renamed = sdk_bridge::rename_variable(function_address, old_name, new_name, stack)
        .map_err(ToolError::IdaError)?;
    if !renamed {
        return Err(ToolError::IdaError(format!(
            "failed to rename {} variable {old_name:?}",
            if stack { "stack" } else { "local" }
        )));
    }
    Ok(json!({
        "function_address": format!("{function_address:#x}"),
        "old_name": old_name,
        "new_name": new_name,
        "stack": stack,
    }))
}

pub fn handle_survey_metrics(
    idb: &Option<IDB>,
    function_addresses: &[u64],
    string_addresses: &[u64],
) -> Result<Value, ToolError> {
    require_database(idb)?;
    let functions = function_addresses
        .iter()
        .map(|address| {
            let xrefs = crate::ida::handlers::xrefs::handle_xrefs_to(
                idb,
                *address,
                &crate::ida::query::XrefQuery::paged(0, 100_000),
            )?
            .xrefs
            .len();
            let incoming_calls =
                crate::ida::handlers::controlflow::handle_callers(idb, *address)?.len();
            let outgoing_calls =
                crate::ida::handlers::controlflow::handle_callees(idb, *address)?.len();
            Ok(json!({
                "address": format!("{address:#x}"),
                "xrefs": xrefs,
                "incoming_calls": incoming_calls,
                "outgoing_calls": outgoing_calls,
            }))
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    let strings = string_addresses
        .iter()
        .map(|address| {
            let xrefs = crate::ida::handlers::xrefs::handle_xrefs_to(
                idb,
                *address,
                &crate::ida::query::XrefQuery::paged(0, 100_000),
            )?
            .xrefs
            .len();
            Ok(json!({
                "address": format!("{address:#x}"),
                "xrefs": xrefs,
            }))
        })
        .collect::<Result<Vec<_>, ToolError>>()?;
    Ok(json!({"functions": functions, "strings": strings}))
}

pub fn handle_signature_bytes(
    idb: &Option<IDB>,
    address: u64,
    size: usize,
    wildcard_operands: bool,
) -> Result<Value, ToolError> {
    let db = require_database(idb)?;
    if size == 0 || size > 1_000_000 {
        return Err(ToolError::InvalidParams(
            "signature size must be between 1 and 1000000 bytes".to_string(),
        ));
    }
    let bytes = db.get_bytes(address, size);
    if bytes.len() != size {
        return Err(ToolError::AddressOutOfRange(address));
    }
    let mask = if wildcard_operands {
        sdk_bridge::operand_mask(address, size).ok_or_else(|| {
            ToolError::IdaError("failed to derive instruction operand mask".to_string())
        })?
    } else {
        vec![true; size]
    };
    Ok(json!({
        "address": format!("{address:#x}"),
        "bytes": crate::ida::handlers::hex_encode(&bytes),
        "mask": mask
            .into_iter()
            .map(|exact| if exact { 'x' } else { '?' })
            .collect::<String>(),
    }))
}

pub fn handle_set_operand_type(
    idb: &Option<IDB>,
    address: u64,
    operand: i32,
    kind: &str,
    target: Option<u64>,
    struct_name: Option<&str>,
    delta: i64,
) -> Result<Value, ToolError> {
    require_database(idb)?;
    let applied = sdk_bridge::set_operand_type(address, operand, kind, target, struct_name, delta)
        .map_err(ToolError::IdaError)?;
    if !applied {
        return Err(ToolError::IdaError(
            "operand type operation returned false".to_string(),
        ));
    }
    Ok(json!({
        "address": format!("{address:#x}"),
        "operand": operand,
        "kind": kind,
    }))
}

pub fn handle_make_data(
    idb: &Option<IDB>,
    address: u64,
    declaration: &str,
    name: Option<&str>,
    delete_existing: bool,
) -> Result<Value, ToolError> {
    let db = require_database(idb)?;
    let size = sdk_bridge::make_data(address, declaration, delete_existing)
        .map_err(ToolError::IdaError)?
        .ok_or_else(|| ToolError::IdaError("failed to create typed data".to_string()))?;
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        db.set_name(address, name)?;
    }
    Ok(json!({
        "address": format!("{address:#x}"),
        "size": size,
        "name": name,
        "type": declaration,
    }))
}
