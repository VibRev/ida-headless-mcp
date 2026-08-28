//! Disassembly listing output types.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One address's listing within a multi-address `disasm` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisasmBatchEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// Text listing starting at `address`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm: Option<String>,
    /// Why this address could not be disassembled; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `disasm` output.
///
/// One requested address fills `address`/`disasm`; several fill `results`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisasmOutput {
    /// The requested address, hex-formatted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Text listing starting at `address`, one instruction per line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disasm: Option<String>,
    /// One entry per address when several were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<DisasmBatchEntry>>,
}

/// `disasm_by_name` / `disasm_function_at` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FunctionDisasmOutput {
    /// Text listing of the function, one instruction per line.
    pub disasm: String,
}
