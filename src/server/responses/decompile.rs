//! Hex-Rays decompilation and `pseudocode_at` output types.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One address's pseudocode within a multi-address `decompile` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecompileBatchEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// Pseudocode of the function containing `address`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decompile: Option<String>,
    /// Why this address could not be decompiled; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `decompile` output.
///
/// One requested address fills `address`/`code`; several fill `results`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecompileOutput {
    /// The requested address, hex-formatted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Hex-Rays pseudocode for the function containing `address`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// One entry per address when several were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<DecompileBatchEntry>>,
}

/// One Hex-Rays statement inside a [`PseudocodeAtOutput`].
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeStatement {
    pub address: String,
    pub text: String,
    /// Hex-Rays opcode id as the decompiler reports it.
    pub opcode: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounds: Option<PseudocodeBounds>,
}

/// Address range a statement covers.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeBounds {
    pub start: String,
    pub end: String,
}

/// Function the [`PseudocodeAtOutput`] statements came from.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeFunction {
    pub address: String,
    pub name: String,
    pub start: String,
    pub end: String,
}

/// One address's answer inside a multi-address `pseudocode_at` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeAtBatchEntry {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pseudocode: Option<PseudocodeAtSingle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Single-address `pseudocode_at` payload. Also nested under `pseudocode`
/// on the batch arm.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeAtSingle {
    pub function: PseudocodeFunction,
    pub query_address: String,
    pub query_end_address: Option<String>,
    pub eamap_ready: bool,
    pub statements: Vec<PseudocodeStatement>,
    pub count: usize,
}

/// `pseudocode_at` output.
///
/// One requested address fills the single-address fields; several fill
/// `results`. Same two-arm convention as [`DecompileOutput`].
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PseudocodeAtOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<PseudocodeFunction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_end_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eamap_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statements: Option<Vec<PseudocodeStatement>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<PseudocodeAtBatchEntry>>,
}
