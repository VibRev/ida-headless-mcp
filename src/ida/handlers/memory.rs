//! Memory read/write handlers.

use crate::error::ToolError;
use crate::ida::handlers::{hex_encode, resolve_address};
use crate::ida::int_spec::IntSpec;
use crate::ida::types::BytesResult;
use idalib::IDB;
use serde_json::{json, Value};

pub fn handle_get_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    size: usize,
) -> Result<BytesResult, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;

    // Limit size to prevent huge reads
    let size = size.min(0x10000); // 64KB max

    let bytes = db.get_bytes(addr, size);

    Ok(BytesResult {
        address: format!("{:#x}", addr),
        bytes: hex_encode(&bytes),
        length: bytes.len(),
    })
}

pub fn handle_patch_bytes(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    bytes: &[u8],
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    db.patch_bytes(addr, bytes)?;
    Ok(json!({
        "address": format!("{:#x}", addr),
        "length": bytes.len(),
    }))
}

pub fn handle_patch_asm(
    idb: &Option<IDB>,
    addr: Option<u64>,
    name: Option<&str>,
    offset: i64,
    line: &str,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let addr = resolve_address(idb, addr, name, offset)?;
    let bytes = db
        .assemble_line(addr, line)
        .map_err(|e| ToolError::IdaError(e.to_string()))?;
    db.patch_bytes(addr, &bytes)?;
    let hex = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(json!({
        "address": format!("{:#x}", addr),
        "line": line,
        "length": bytes.len(),
        "bytes": hex,
    }))
}

/// Read one typed integer.
///
/// Goes through raw bytes rather than `get_word`/`get_dword`: those return the
/// database's byte order, and the whole point of [`IntSpec`] is being able to
/// ask for the other one.
pub fn handle_get_int(idb: &Option<IDB>, addr: u64, spec: IntSpec) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let width = spec.width.bytes();
    let bytes = db.get_bytes(addr, width);
    let value = spec.decode(&bytes, db.meta().is_be())?;

    Ok(json!({
        "address": format!("{addr:#x}"),
        "ty": spec.to_string(),
        "size": width,
        "value": value.to_string(),
        "hex": format!("{:#x}", value as u64 & u64::MAX >> (64 - width * 8)),
        "bytes": hex_encode(&bytes),
    }))
}

/// Write one typed integer, refusing a value the width cannot hold.
pub fn handle_put_int(
    idb: &Option<IDB>,
    addr: u64,
    spec: IntSpec,
    value: i128,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let bytes = spec.encode(value, db.meta().is_be())?;
    db.patch_bytes(addr, &bytes)?;

    Ok(json!({
        "address": format!("{addr:#x}"),
        "ty": spec.to_string(),
        "size": bytes.len(),
        "value": value.to_string(),
        "bytes": hex_encode(&bytes),
    }))
}

pub fn handle_read_int(idb: &Option<IDB>, addr: u64, size: usize) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let value = match size {
        1 => db.get_byte(addr) as u64,
        2 => db.get_word(addr) as u64,
        4 => db.get_dword(addr) as u64,
        8 => db.get_qword(addr),
        _ => {
            return Err(ToolError::IdaError(format!(
                "unsupported integer size: {}",
                size
            )));
        }
    };

    Ok(json!({
        "address": format!("{:#x}", addr),
        "size": size,
        "value": value,
        "hex": format!("0x{:x}", value)
    }))
}
