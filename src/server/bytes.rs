//! Byte formatting and integer-read helpers used by memory tools.

use crate::error::ToolError;
use crate::ida::int_spec::IntSpec;
use crate::ida::worker::IdaWorker;
use crate::server::address::AddressArg;
use rmcp::model::CallToolResult;
use rmcp::ErrorData as McpError;
use serde_json::{json, Value};
use std::sync::Arc;

use super::{structured_json, structured_value};

pub(crate) fn value_to_bytes(value: &Value) -> Result<Vec<u8>, ToolError> {
    match value {
        Value::String(s) => {
            let mut cleaned = String::with_capacity(s.len());
            for c in s.chars() {
                if c.is_ascii_hexdigit() {
                    cleaned.push(c);
                } else if c.is_ascii_whitespace()
                    || matches!(c, ',' | '_' | ':' | '-')
                    || c == 'x'
                    || c == 'X'
                {
                    continue;
                } else {
                    return Err(ToolError::InvalidParams(format!(
                        "invalid hex character: {c}"
                    )));
                }
            }
            if cleaned.is_empty() {
                return Err(ToolError::InvalidParams("no bytes provided".to_string()));
            }
            if !cleaned.len().is_multiple_of(2) {
                return Err(ToolError::InvalidParams(
                    "hex string has odd length".to_string(),
                ));
            }
            let mut out = Vec::with_capacity(cleaned.len() / 2);
            for i in (0..cleaned.len()).step_by(2) {
                let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
                    .map_err(|_| ToolError::InvalidParams("invalid hex byte".to_string()))?;
                out.push(byte);
            }
            Ok(out)
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                match v {
                    Value::Number(n) => {
                        let byte = n
                            .as_u64()
                            .ok_or_else(|| ToolError::InvalidParams("invalid byte".to_string()))?;
                        if byte > u8::MAX as u64 {
                            return Err(ToolError::InvalidParams(
                                "byte value out of range".to_string(),
                            ));
                        }
                        out.push(byte as u8);
                    }
                    Value::String(s) => {
                        let val = crate::address::parse_address(s)?;
                        if val > u8::MAX as u64 {
                            return Err(ToolError::InvalidParams(
                                "byte value out of range".to_string(),
                            ));
                        }
                        out.push(val as u8);
                    }
                    _ => {
                        return Err(ToolError::InvalidParams(
                            "bytes must be numbers or strings".to_string(),
                        ));
                    }
                }
            }
            if out.is_empty() {
                Err(ToolError::InvalidParams("no bytes provided".to_string()))
            } else {
                Ok(out)
            }
        }
        Value::Number(n) => {
            let byte = n
                .as_u64()
                .ok_or_else(|| ToolError::InvalidParams("invalid byte".to_string()))?;
            if byte > u8::MAX as u64 {
                return Err(ToolError::InvalidParams(
                    "byte value out of range".to_string(),
                ));
            }
            Ok(vec![byte as u8])
        }
        _ => Err(ToolError::InvalidParams(
            "expected hex string or array of bytes".to_string(),
        )),
    }
}

pub(crate) async fn get_int_values(
    worker: &Arc<IdaWorker>,
    address: AddressArg,
    size: usize,
) -> Result<CallToolResult, McpError> {
    let addrs = match address.to_addresses() {
        Ok(v) => v,
        Err(e) => return Ok(e.to_tool_result()),
    };

    if addrs.len() == 1 {
        match worker.read_int(addrs[0], size).await {
            Ok(result) => Ok(structured_value(&result, "get_int")),
            Err(e) => Ok(e.to_tool_result()),
        }
    } else {
        let mut results = Vec::new();
        for addr in addrs {
            match worker.read_int(addr, size).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "value": result
                })),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(structured_json(json!({ "results": results })))
    }
}

/// Parse a `put_int` value: a JSON number, or a decimal / `0x` string.
///
/// A string is the documented spelling because JSON numbers cannot carry the
/// far ends of `i64`/`u64` without loss, but a number is accepted for the
/// values that do survive the trip.
pub(crate) fn parse_signed_value(value: &Value) -> Result<i128, ToolError> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .ok_or_else(|| {
                ToolError::InvalidParams(format!("'{n}' is not an integer; pass it as a string"))
            }),
        Value::String(s) => {
            let token = s.trim();
            let (negative, digits) = match token.strip_prefix('-') {
                Some(rest) => (true, rest.trim_start()),
                None => (false, token.strip_prefix('+').unwrap_or(token)),
            };
            let magnitude = match digits
                .strip_prefix("0x")
                .or_else(|| digits.strip_prefix("0X"))
            {
                Some(hex) => i128::from_str_radix(&hex.replace('_', ""), 16),
                None => digits.replace('_', "").parse::<i128>(),
            }
            .map_err(|_| {
                ToolError::InvalidParams(format!(
                    "'{s}' is not an integer; expected decimal or 0x-hex"
                ))
            })?;
            Ok(if negative { -magnitude } else { magnitude })
        }
        _ => Err(ToolError::InvalidParams(
            "value must be an integer or a string holding one".to_string(),
        )),
    }
}

/// Read one typed integer per address, batching the same way `get_u*` does.
pub(crate) async fn get_typed_int_values(
    worker: &Arc<IdaWorker>,
    address: AddressArg,
    spec: IntSpec,
) -> Result<CallToolResult, McpError> {
    let addrs = match address.to_addresses() {
        Ok(v) => v,
        Err(e) => return Ok(e.to_tool_result()),
    };

    if addrs.len() == 1 {
        return match worker.get_int(addrs[0], spec).await {
            Ok(result) => Ok(structured_value(&result, "get_int")),
            Err(e) => Ok(e.to_tool_result()),
        };
    }

    let mut results = Vec::new();
    for addr in addrs {
        match worker.get_int(addr, spec).await {
            Ok(result) => results.push(result),
            Err(e) => results.push(json!({
                "address": format!("{addr:#x}"),
                "error": e.to_string()
            })),
        }
    }
    Ok(structured_json(json!({ "results": results })))
}

pub(crate) fn trim_bytes_le(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    while out.len() > 1 && out.last() == Some(&0) {
        out.pop();
    }
    out
}

pub(crate) fn trim_bytes_be(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    bytes[start..].to_vec()
}

pub(crate) fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .collect()
}
