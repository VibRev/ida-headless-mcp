//! `run_script` output type.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `run_script` output. Failure is `isError: true`; this is the success arm.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunScriptOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
}
