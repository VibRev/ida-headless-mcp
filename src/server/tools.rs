// Tool implementations, split by catalog-ish domain.
//
// Each file is its own `#[vibrev_tool_router]` impl so the proc macro can see
// the tools (include! into one impl does not work). `tool_router()` /
// `vibrev_tool_defs()` / `vibrev_cli()` / `vibrev_call()` are assembled here
// so callers keep the names they already use.
include!("tools/database.rs");
include!("tools/composite.rs");
include!("tools/functions.rs");
include!("tools/metadata.rs");
include!("tools/memory.rs");
include!("tools/xrefs.rs");
include!("tools/controlflow.rs");
include!("tools/types.rs");
include!("tools/editing.rs");

impl IdaMcpServer {
    pub fn tool_router() -> ToolRouter<Self> {
        Self::database_router()
            + Self::composite_router()
            + Self::functions_router()
            + Self::metadata_router()
            + Self::memory_router()
            + Self::xrefs_router()
            + Self::controlflow_router()
            + Self::types_router()
            + Self::editing_router()
    }

    pub fn vibrev_tool_defs() -> Vec<vibrev_kit::ToolDef> {
        let mut defs = Self::database_defs();
        defs.extend(Self::composite_defs());
        defs.extend(Self::functions_defs());
        defs.extend(Self::metadata_defs());
        defs.extend(Self::memory_defs());
        defs.extend(Self::xrefs_defs());
        defs.extend(Self::controlflow_defs());
        defs.extend(Self::types_defs());
        defs.extend(Self::editing_defs());
        defs
    }

    pub fn vibrev_cli(bin: &'static str) -> vibrev_kit::cli::EngineCli {
        vibrev_kit::cli::EngineCli::new(bin, Self::vibrev_tool_defs())
    }

    pub async fn vibrev_call(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<vibrev_kit::ToolOutcome, rmcp::ErrorData> {
        if let Some(result) = self.try_database_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_composite_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_functions_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_metadata_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_memory_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_xrefs_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_controlflow_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_types_call(name, args.clone()).await {
            return result;
        }
        if let Some(result) = self.try_editing_call(name, args.clone()).await {
            return result;
        }
        Err(rmcp::ErrorData::invalid_params(
            format!("unknown tool: {name}"),
            None,
        ))
    }
}
