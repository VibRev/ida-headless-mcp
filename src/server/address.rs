//! Address request parameters shared by MCP tools.
//!
//! Clients send a string, number, array, comma-separated string, or a JSON
//! array string; this type is that contract with a named schema, so the accepted
//! shapes are published once rather than restated at each call site.

use crate::error::ToolError;
use rmcp::schemars::JsonSchema;
use schemars::{json_schema, Schema, SchemaGenerator};
use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::Value;
use std::borrow::Cow;
use std::fmt;

pub use crate::address::parse_address;

/// One or more addresses in the shapes MCP clients already send.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressArg(Value);

impl AddressArg {
    /// Tokens as they arrived, before address parsing.
    pub fn to_strings(&self) -> Result<Vec<String>, ToolError> {
        value_to_strings(&self.0)
    }

    pub fn to_addresses(&self) -> Result<Vec<u64>, ToolError> {
        value_to_addresses(&self.0)
    }

    pub fn to_single(&self) -> Result<u64, ToolError> {
        value_to_single_address(&self.0)
    }

    pub fn to_exactly_one(&self, field_name: &str) -> Result<u64, ToolError> {
        value_to_exactly_one_address(&self.0, field_name)
    }
}

/// Flatten a leftover untyped `Value` the same way [`AddressArg::to_single`] does.
/// Used by `sdk_mutation.value`, which is an integer, not an address field.
pub(crate) fn value_to_single_address(value: &Value) -> Result<u64, ToolError> {
    let addrs = value_to_addresses(value)?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| ToolError::InvalidAddress("empty address list".to_string()))
}

fn value_to_addresses(value: &Value) -> Result<Vec<u64>, ToolError> {
    let strings = value_to_strings(value)?;
    if strings.is_empty() {
        return Err(ToolError::InvalidAddress(
            "no addresses provided".to_string(),
        ));
    }
    strings.iter().map(|s| parse_address(s)).collect()
}

fn value_to_exactly_one_address(value: &Value, field_name: &str) -> Result<u64, ToolError> {
    let addresses = value_to_addresses(value)?;
    match addresses.as_slice() {
        [address] => Ok(*address),
        _ => Err(ToolError::InvalidParams(format!(
            "{field_name} must contain exactly one value"
        ))),
    }
}

pub(crate) fn value_to_strings(value: &Value) -> Result<Vec<String>, ToolError> {
    match value {
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.starts_with('[')
                && let Ok(Value::Array(arr)) = serde_json::from_str(trimmed)
            {
                let mut out = Vec::with_capacity(arr.len());
                for v in &arr {
                    match v {
                        Value::String(s) => out.push(s.to_string()),
                        Value::Number(n) => out.push(n.to_string()),
                        _ => {
                            return Err(ToolError::IdaError(
                                "expected string or number".to_string(),
                            ));
                        }
                    }
                }
                return Ok(out);
            }
            if trimmed.contains(',') {
                Ok(trimmed
                    .split(',')
                    .map(|t| t.trim())
                    .filter(|t| !t.is_empty())
                    .map(|t| t.to_string())
                    .collect())
            } else if trimmed.is_empty() {
                Err(ToolError::IdaError("empty string".to_string()))
            } else {
                Ok(vec![trimmed.to_string()])
            }
        }
        Value::Number(n) => Ok(vec![n.to_string()]),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                match v {
                    Value::String(s) => out.push(s.to_string()),
                    Value::Number(n) => out.push(n.to_string()),
                    _ => {
                        return Err(ToolError::IdaError("expected string or number".to_string()));
                    }
                }
            }
            Ok(out)
        }
        _ => Err(ToolError::IdaError(
            "expected string, number, or array".to_string(),
        )),
    }
}

impl<'de> Deserialize<'de> for AddressArg {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::String(_) | Value::Number(_) | Value::Array(_) => Ok(Self(value)),
            _ => Err(de::Error::custom("expected string, number, or array")),
        }
    }
}

impl JsonSchema for AddressArg {
    fn schema_name() -> Cow<'static, str> {
        "AddressArg".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::AddressArg").into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [
                { "type": "string" },
                { "type": "number" },
                {
                    "type": "array",
                    "items": {
                        "anyOf": [
                            { "type": "string" },
                            { "type": "number" }
                        ]
                    }
                }
            ]
        })
    }
}

impl fmt::Display for AddressArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn arg(value: Value) -> AddressArg {
        serde_json::from_value(value).expect("valid AddressArg")
    }

    #[test]
    fn hex_string() {
        assert_eq!(arg(json!("0x1000")).to_addresses().unwrap(), vec![0x1000]);
    }

    #[test]
    fn decimal_number() {
        assert_eq!(arg(json!(4096)).to_addresses().unwrap(), vec![4096]);
    }

    #[test]
    fn comma_separated_string() {
        assert_eq!(
            arg(json!("0x1000,0x2000")).to_addresses().unwrap(),
            vec![0x1000, 0x2000]
        );
    }

    #[test]
    fn mixed_array() {
        assert_eq!(
            arg(json!([0x1000, "0x2000"])).to_addresses().unwrap(),
            vec![0x1000, 0x2000]
        );
    }

    #[test]
    fn json_array_string() {
        assert_eq!(
            arg(json!("[4096, \"0x2000\"]")).to_addresses().unwrap(),
            vec![4096, 0x2000]
        );
    }

    #[test]
    fn binary_and_underscores() {
        assert_eq!(parse_address("0b1010").unwrap(), 0b1010);
        assert_eq!(parse_address("0x1_000").unwrap(), 0x1000);
        assert_eq!(parse_address("4_096").unwrap(), 4096);
        assert_eq!(arg(json!("0b1010")).to_single().unwrap(), 0b1010);
        assert_eq!(arg(json!("0x1_000")).to_single().unwrap(), 0x1000);
    }

    #[test]
    fn empty_string_is_error() {
        let err = arg(json!("")).to_addresses().unwrap_err();
        assert!(err.to_string().contains("empty string"));
    }

    #[test]
    fn bad_hex_is_error() {
        let err = arg(json!("0xzz")).to_addresses().unwrap_err();
        match err {
            ToolError::InvalidAddress(s) => assert_eq!(s, "0xzz"),
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn to_exactly_one_rejects_multiple() {
        let err = arg(json!(["0x1000", "0x2000"]))
            .to_exactly_one("address")
            .unwrap_err();
        match err {
            ToolError::InvalidParams(s) => {
                assert_eq!(s, "address must contain exactly one value");
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    #[test]
    fn to_exactly_one_accepts_one() {
        assert_eq!(
            arg(json!("0x1000")).to_exactly_one("address").unwrap(),
            0x1000
        );
    }

    #[test]
    fn to_single_takes_first_of_several() {
        assert_eq!(
            arg(json!(["0x1000", "0x2000"])).to_single().unwrap(),
            0x1000
        );
    }

    #[test]
    fn empty_array_is_error() {
        let err = arg(json!([])).to_addresses().unwrap_err();
        match err {
            ToolError::InvalidAddress(s) => assert_eq!(s, "no addresses provided"),
            other => panic!("expected InvalidAddress, got {other:?}"),
        }
    }

    #[test]
    fn rejects_object_at_deserialize() {
        let err = serde_json::from_value::<AddressArg>(json!({"ea": "0x1"})).unwrap_err();
        assert!(err
            .to_string()
            .contains("expected string, number, or array"));
    }

    #[test]
    fn optional_missing_and_null() {
        #[derive(Deserialize)]
        struct Wrap {
            address: Option<AddressArg>,
        }
        let missing: Wrap = serde_json::from_value(json!({})).unwrap();
        assert!(missing.address.is_none());
        let null: Wrap = serde_json::from_value(json!({"address": null})).unwrap();
        assert!(null.address.is_none());
    }

    #[test]
    fn schema_is_string_number_or_array() {
        let schema = schemars::schema_for!(AddressArg);
        let any_of = schema
            .get("anyOf")
            .and_then(Value::as_array)
            .expect("AddressArg schema is anyOf");
        let types: Vec<&str> = any_of
            .iter()
            .filter_map(|branch| branch.get("type").and_then(Value::as_str))
            .collect();
        assert_eq!(types, ["string", "number", "array"]);
        let items = &any_of[2]["items"]["anyOf"];
        let item_types: Vec<&str> = items
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|branch| branch.get("type").and_then(Value::as_str))
            .collect();
        assert_eq!(item_types, ["string", "number"]);
    }
}
