//! Tool catalog and help output types.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One tool in a catalog listing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogTool {
    /// Tool name to pass to `tools/call`.
    pub name: String,
    /// First sentence of the tool's description.
    pub description: Option<String>,
    /// Category the tool belongs to.
    pub category: Option<String>,
}

/// One category in a catalog overview.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogCategory {
    /// Category name to pass back as `category`.
    pub category: String,
    /// What the category covers.
    pub description: String,
    /// Number of tools in the category that the active filter leaves enabled.
    pub tool_count: usize,
}

/// `tool_catalog` output.
///
/// Without arguments it lists `categories`; with `category` or `query` it
/// lists matching `tools` and echoes the argument back.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolCatalogOutput {
    /// Every category, with enabled-tool counts. Present when no argument was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<CatalogCategory>>,
    /// Matching tools. Present when `category` or `query` was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<CatalogTool>>,
    /// How many tools matched before `limit` cut the list, alongside `tools`.
    ///
    /// The default limit is seven, so a search that matches twenty answers with
    /// seven — and without this, seven matches and seven-of-twenty are the same
    /// payload. A caller reading it decides there is nothing else to try.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,
    /// The category that was listed, echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// What the listed category covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_description: Option<String>,
    /// The query that was searched, echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// What to do next.
    pub hint: String,
    /// True when `--toolsets`/`--tools`/`--exclude-tools`/`--read-only` is narrowing the surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtering_active: Option<bool>,
    /// How many tools the active filter leaves enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_tool_count: Option<usize>,
}

/// `tool_help` output.
///
/// A known, enabled tool fills `name`/`description`/`parameters`; an unknown
/// or filtered-out one fills `error` instead.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolHelpOutput {
    /// Tool name to pass to `tools/call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Category the tool belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Full description, as advertised on `tools/list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The tool's JSON Schema for arguments, as advertised on `tools/list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// The tool's safety annotations, as advertised on `tools/list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    /// Why no documentation could be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Tool names close to the requested one; present when it was not found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<String>>,
    /// What to do next; present alongside `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// True when the tool exists but the active filter disabled it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filtering_active: Option<bool>,
}
