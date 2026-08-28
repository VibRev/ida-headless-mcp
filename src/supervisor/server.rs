use super::resource;
use super::session::{OpenSessionRequest, SessionHealth, SessionHealthList, SessionManager};
use crate::server::catalog;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock as Content,
    ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ReadResourceRequestParams, ReadResourceResponse, Resource, ResourceTemplate,
    ServerCapabilities, ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use vibrev_kit::policy::ToolPolicy;

/// Session lifecycle tools implemented by the supervisor itself.
pub const SESSION_TOOLS: &[&str] = &["idb_open", "idb_list", "idb_close", "server_health"];

/// Native tools the supervisor deliberately does not route. Database
/// lifecycle belongs to the supervisor's session table: a worker-local
/// `open_idb` / `open_dsc` / `close_idb` would desynchronize it. Clients use
/// `idb_open` / `idb_close` instead.
const SUPERVISOR_OWNED_LIFECYCLE: &[&str] = &["open_idb", "open_dsc", "close_idb"];

/// Tools hidden unless the server is started with `--unsafe`. `run_script`
/// executes arbitrary IDAPython inside the worker process.
pub const UNSAFE_TOOLS: &[&str] = &["run_script"];

/// Returns true when a native tool is routable through the supervisor.
pub fn is_routable_tool(name: &str) -> bool {
    catalog::native_tool_name(name).is_some() && !SUPERVISOR_OWNED_LIFECYCLE.contains(&name)
}

/// Every public name the supervisor can advertise, before filtering.
pub fn public_tool_names() -> impl Iterator<Item = &'static str> {
    catalog::native_tool_names()
        .filter(|name| !SUPERVISOR_OWNED_LIFECYCLE.contains(name))
        .chain(SESSION_TOOLS.iter().copied())
}

pub fn is_unsafe_tool(name: &str) -> bool {
    UNSAFE_TOOLS.contains(&name)
}

#[derive(Clone)]
pub struct SupervisorServer {
    sessions: SessionManager,
    unsafe_enabled: bool,
    filter: Arc<ToolPolicy>,
}

#[derive(Debug, Deserialize)]
struct IdOpenParams {
    input_path: String,
    #[serde(default = "default_open_mode")]
    mode: String,
    #[serde(default = "default_true")]
    run_auto_analysis: bool,
    #[serde(default = "default_true")]
    build_caches: bool,
    #[serde(default = "default_true")]
    init_hexrays: bool,
    #[serde(default = "default_idle_ttl")]
    idle_ttl_sec: u64,
    #[serde(default)]
    preferred_session_id: String,
}

#[derive(Debug, Deserialize)]
struct IdCloseParams {
    database: String,
    #[serde(default = "default_true")]
    save: bool,
}

#[derive(Debug, Deserialize)]
struct ServerHealthParams {
    #[serde(default)]
    database: Option<String>,
}

impl SupervisorServer {
    /// The output net is not here. It wraps this server from the outside —
    /// `vibrev_kit::output::Capped` — so that a tool added to the catalog is
    /// covered on the day it lands rather than on the day someone remembers to
    /// route it through a cache.
    pub fn new(sessions: SessionManager, unsafe_enabled: bool, filter: Arc<ToolPolicy>) -> Self {
        Self {
            sessions,
            unsafe_enabled,
            filter,
        }
    }

    /// Builds the public catalog without starting an IDA worker.
    pub fn advertised_tools(unsafe_enabled: bool) -> Result<Vec<Tool>, String> {
        Self::advertised_tools_with_filter(unsafe_enabled, &ToolPolicy::unrestricted())
    }

    /// Every tool this face can ever advertise, with nothing applied.
    ///
    /// What a [`ToolPolicy`](vibrev_kit::policy::ToolPolicy) is built against:
    /// a name is legal in `--tools` exactly when a client could have seen it
    /// with no flags set. Includes the unsafe tools, because the gate that hides
    /// them is a separate door and not the policy's business.
    pub fn unfiltered_catalog() -> Vec<Tool> {
        Self::advertised_tools(true).expect("the unfiltered catalog always builds")
    }

    /// Builds the public catalog after applying the supervisor filter and the
    /// independent unsafe-tool gate.
    ///
    /// Worker tools come straight from the native `#[tool]` router, with the
    /// session selector (`database`) spliced into each input schema; the
    /// supervisor contributes the session lifecycle tools.
    pub fn advertised_tools_with_filter(
        unsafe_enabled: bool,
        filter: &ToolPolicy,
    ) -> Result<Vec<Tool>, String> {
        let mut tools = catalog::native_tools();
        tools.retain(|tool| {
            let name = tool.name.as_ref();
            is_routable_tool(name)
                && filter.allows(name)
                && (unsafe_enabled || !is_unsafe_tool(name))
        });
        for tool in &mut tools {
            inject_database_argument(tool)?;
            adapt_output_schema_for_supervisor(tool);
        }

        tools.extend(
            session_tools()
                .into_iter()
                .filter(|tool| filter.allows(tool.name.as_ref())),
        );
        Ok(tools)
    }

    fn tools(&self) -> Result<Vec<Tool>, String> {
        Self::advertised_tools_with_filter(self.unsafe_enabled, &self.filter)
    }

    async fn call_management(
        &self,
        name: &str,
        arguments: Map<String, Value>,
        cancel: CancellationToken,
    ) -> Result<Value, String> {
        match name {
            "idb_open" => {
                let params = serde_json::from_value::<IdOpenParams>(Value::Object(arguments))
                    .map_err(|error| format!("Invalid idb_open arguments: {error}"))?;
                let preferred_session_id = (!params.preferred_session_id.trim().is_empty())
                    .then_some(params.preferred_session_id);
                let request = OpenSessionRequest {
                    input_path: params.input_path,
                    mode: params.mode,
                    run_auto_analysis: params.run_auto_analysis,
                    build_caches: params.build_caches,
                    init_hexrays: params.init_hexrays,
                    idle_ttl_sec: params.idle_ttl_sec,
                    preferred_session_id,
                };
                serde_json::to_value(
                    self.sessions
                        .open(request, Some(cancel))
                        .await
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("Failed to serialize idb_open result: {error}"))
            }
            "idb_list" => {
                let sessions = self.sessions.list().await;
                Ok(json!({"count": sessions.len(), "sessions": sessions}))
            }
            "idb_close" => {
                let params = serde_json::from_value::<IdCloseParams>(Value::Object(arguments))
                    .map_err(|error| format!("Invalid idb_close arguments: {error}"))?;
                serde_json::to_value(
                    self.sessions
                        .close(&params.database, params.save)
                        .await
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("Failed to serialize idb_close result: {error}"))
            }
            "server_health" => {
                let params = serde_json::from_value::<ServerHealthParams>(Value::Object(arguments))
                    .map_err(|error| format!("Invalid server_health arguments: {error}"))?;
                let database = params
                    .database
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty());
                serde_json::to_value(
                    self.sessions
                        .health(database)
                        .await
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| format!("Failed to serialize server_health result: {error}"))
            }
            _ => Err(format!("Unknown management tool '{name}'")),
        }
    }

    /// Routes a public tool call straight to the native tool of the same name
    /// on the worker that owns `database`.
    async fn call_worker(
        &self,
        name: &str,
        mut arguments: Map<String, Value>,
        cancel: CancellationToken,
    ) -> Result<CallToolResult, String> {
        if !is_routable_tool(name) {
            return Err(unknown_tool_message(name));
        }
        if is_unsafe_tool(name) && !self.unsafe_enabled {
            return Err(format!(
                "Tool '{name}' is unsafe and disabled; restart with --unsafe"
            ));
        }
        let database = arguments
            .remove("database")
            .and_then(|value| value.as_str().map(str::to_string))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "Missing required argument 'database'. Session ID returned by idb_open. Use idb_list to enumerate open databases.".to_string()
            })?;
        self.sessions
            .call_native_result(&database, name, arguments, Some(cancel))
            .await
            .map_err(|error| error.to_string())
    }
}

impl ServerHandler for SupervisorServer {
    /// The same list the worker face offers, not a shorter one.
    ///
    /// A hardcoded list here goes stale in silence, and it matters more than it
    /// looks: the supervisor is the default command, so every client that does
    /// not spell out `worker` would be told the newest protocol version does
    /// not exist. Delegating is the only way the two faces cannot drift.
    ///
    /// Nothing here is bound to a transport session. A supervisor request names
    /// its database with the `database` argument, so routing does not need the
    /// connection to carry identity — which is what the sessionless lifecycle
    /// asks for.
    fn supported_protocol_versions(&self) -> Cow<'static, [rmcp::model::ProtocolVersion]> {
        crate::server::supported_protocol_versions()
    }

    fn get_info(&self) -> ServerInfo {
        // No `.enable_prompts()`. This server implements neither `prompts/list`
        // nor `prompts/get`, so the capability is pure advertisement: rmcp
        // answers the list with an empty one and `prompts/get` with
        // method-not-found, leaving a client that renders a prompt picker from
        // capabilities with an empty picker. Declare it back together with an
        // implementation, not before one.
        let mut info = ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_instructions(
                "Open databases with idb_open, pass the returned session_id as database to every analysis tool, and close sessions with idb_close. Resource reads use the sole open database automatically; when multiple databases are open, append ?database=<session_id> to the resource URI.",
            );
        // `ServerInfo::new` defaults `server_info` to
        // `Implementation::from_build_env()`, which expands
        // `env!("CARGO_CRATE_NAME")` inside rmcp's own compilation unit and
        // therefore reports "rmcp". The env! calls below must stay in this
        // crate so they resolve to this package.
        info.server_info = crate::server_implementation();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.tools()
            .map(ListToolsResult::with_all_items)
            .map_err(|error| McpError::internal_error(error, None))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools()
            .ok()?
            .into_iter()
            .find(|tool| tool.name.as_ref() == name)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let is_session_tool = SESSION_TOOLS.contains(&name.as_str());
        if (is_session_tool || is_routable_tool(&name)) && !self.filter.allows(&name) {
            return Err(McpError::invalid_params(disabled_tool_message(&name), None));
        }
        let arguments = request.arguments.unwrap_or_default();
        let cancel = context.ct;
        let result = if is_session_tool {
            management_tool_result(self.call_management(&name, arguments, cancel).await)
        } else {
            match self.call_worker(&name, arguments, cancel).await {
                // Verbatim. A worker's answer is already a `CallToolResult`, and
                // rebuilding one here is how the pretty rendering it chose gets
                // replaced by compact JSON, and how an error message it wrote
                // gets buried in an `{"error": …}` envelope. Both were real
                // enough to have tests; those tests are gone because there is no
                // longer a step between the worker and the wire that could do it.
                Ok(result) => result,
                Err(error) => tool_result(json!({"error": error}), true),
            }
        };
        Ok(result.into())
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(resources()))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult::with_all_items(
            resource_templates(),
        ))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        resource::read(&self.sessions, &request.uri).await
    }
}

/// `idb_list` output: the session table, exactly as `call_management` builds it.
#[derive(serde::Serialize, rmcp::schemars::JsonSchema)]
struct IdbListOutput {
    /// Number of entries in `sessions`.
    count: usize,
    /// One entry per open database session.
    sessions: Vec<super::session::SessionInfo>,
}

/// Session lifecycle tools. Their schemas are declared here because they are
/// implemented by the supervisor, not by any `#[tool]` on the worker.
fn session_tools() -> Vec<Tool> {
    vec![
        tool(
            "idb_open",
            "Open a binary and warm it up. Returns the existing session if the file is already \
             open under the supervisor; otherwise creates one according to `mode`.",
            json!({
                "type": "object",
                "properties": {
                    "input_path": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "mode": {
                        "type": "string",
                        "default": "prefer_headless",
                        "description": "How to open: prefer_headless (default), force_headless, or prefer_gui. force_gui is rejected by the headless server.",
                    },
                    "run_auto_analysis": {
                        "type": "boolean",
                        "default": true,
                        "description": "Run automatic analysis on the binary",
                    },
                    "build_caches": {
                        "type": "boolean",
                        "default": true,
                        "description": "Build core caches after open",
                    },
                    "init_hexrays": {
                        "type": "boolean",
                        "default": true,
                        "description": "Initialize the Hex-Rays decompiler after open",
                    },
                    "idle_ttl_sec": {
                        "type": "integer",
                        "default": 600,
                        "description": "Idle seconds before the session is reaped and its worker released (0 disables reaping).",
                    },
                    "preferred_session_id": {
                        "type": "string",
                        "default": "",
                        "description": "Preferred session ID (auto-generated when empty). 1-128 ASCII letters, digits, '-', '_', or '.'.",
                    },
                },
                "required": ["input_path"],
            }),
            session_output_schema::<super::session::OpenSessionResult>(),
        ),
        tool(
            "idb_list",
            "List open database sessions with their session IDs and metadata.",
            json!({"type": "object", "properties": {}, "required": []}),
            session_output_schema::<IdbListOutput>(),
        ),
        tool(
            "idb_close",
            "Close a session: optionally save it, unregister it from the supervisor, and \
             terminate its worker (freeing a worker slot).",
            json!({
                "type": "object",
                "properties": {
                    "database": {
                        "type": "string",
                        "description": "Session ID returned by idb_open (see idb_list).",
                    },
                    "save": {
                        "type": "boolean",
                        "default": true,
                        "description": "Save the database before closing",
                    },
                },
                "required": ["database"],
            }),
            session_output_schema::<super::session::CloseSessionResult>(),
        ),
        tool(
            "server_health",
            "Report whether a session is executing a native tool, without waiting on the IDA \
             worker. Omit `database` to snapshot every open session.",
            json!({
                "type": "object",
                "properties": {
                    "database": {
                        "type": "string",
                        "description": "Session ID to probe. Omit to snapshot every open session (same as idb_list).",
                    },
                },
                "required": [],
            }),
            server_health_output_schema(),
        ),
    ]
}

/// Builds a supervisor-owned tool with the same metadata treatment the native
/// `#[tool]` catalog gets: display title and safety annotations come from the
/// single tables in `crate::server`, so the session tools cannot drift away
/// from the routed ones.
fn tool(
    name: &'static str,
    description: &'static str,
    schema: Value,
    output_schema: Arc<rmcp::model::JsonObject>,
) -> Tool {
    let schema = match schema {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    crate::server::apply_tool_metadata(
        Tool::new(name, description, Arc::new(schema)).with_raw_output_schema(output_schema),
    )
}

/// Output schema for a successful supervisor session-tool call. Failures use
/// `isError: true` and carry no `structuredContent`, just like routed tools.
///
/// `schema_for_output` produces a standalone schema *document*, and a document
/// carries the `$schema` dialect key at its root. An `outputSchema` is a schema,
/// not a document: no routed tool publishes that key, and
/// `the_shared_tool_surface_contract_holds` audits every advertised tool for it.
///
/// Only `$schema` goes. `$defs` stays, which is what separates this from
/// [`detach_schema_document_keys`] — that one is for a schema about to be nested
/// inside a larger document, where the `#/$defs/...` pointers would dangle
/// unless the definitions are lifted to the new root. Here the schema really is
/// its own root, so they already resolve.
fn session_output_schema<T>() -> Arc<rmcp::model::JsonObject>
where
    T: rmcp::schemars::JsonSchema + std::any::Any,
{
    let mut schema = (*crate::server::responses::schema::<T>()).clone();
    schema.remove("$schema");
    Arc::new(schema)
}

/// `server_health` has two success shapes: one session or every session.
fn server_health_output_schema() -> Arc<rmcp::model::JsonObject> {
    let mut one = Value::Object((*crate::server::responses::schema::<SessionHealth>()).clone());
    let mut all = Value::Object((*crate::server::responses::schema::<SessionHealthList>()).clone());
    let mut defs = Map::new();
    detach_schema_document_keys(&mut one, &mut defs);
    detach_schema_document_keys(&mut all, &mut defs);

    let mut schema = Map::new();
    schema.insert("anyOf".to_string(), json!([one, all]));
    if !defs.is_empty() {
        schema.insert("$defs".to_string(), Value::Object(defs));
    }
    Arc::new(schema)
}

/// Prepares a standalone schema document to be embedded inside a larger one.
///
/// Two keys only make sense at the root of a schema document, and both break
/// when schemars' output stops being the root:
///
/// - `$schema` describes the dialect of the whole document, not of a branch;
/// - `$defs` is where schemars parks named subschemas, and the `$ref`s pointing
///   at them are absolute JSON Pointers (`#/$defs/SegmentInfo`) resolved
///   against the *document* root. Nesting the document without lifting `$defs`
///   back to the new root leaves every one of those references dangling.
///
/// Strips both from `schema` and merges the definitions into `defs`, which the
/// caller re-attaches at the root it is building.
fn detach_schema_document_keys(schema: &mut Value, defs: &mut Map<String, Value>) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    object.remove("$schema");
    if let Some(Value::Object(inner)) = object.remove("$defs") {
        defs.extend(inner);
    }
}

/// Rewrites a native tool's output schema into the shape the supervisor
/// actually returns.
///
/// Exactly one transformation happens between the worker's `structuredContent`
/// and the client's: [`tool_result`] wraps any non-object payload as
/// `{"result": <payload>}`, so a worker tool that answers with a bare array
/// (`segments`, `imports`, `exports`, `entrypoints`) is an object by the time a
/// client sees it.
///
/// The output cache is not a second transformation. [`OutputCache::compact`]
/// trims the payload in place — every object key survives, only long strings
/// and long arrays are shortened — and moves the truncation bookkeeping to
/// `_meta.ida_mcp`, which no `outputSchema` describes. So the advertised schema
/// is the same whether or not the cache is active, and this function must not
/// grow an `anyOf` arm for a `{truncated, preview, total_chars, output_id,
/// download_url}` envelope: the server does not produce one.
fn adapt_output_schema_for_supervisor(tool: &mut Tool) {
    let Some(native) = tool.output_schema.clone() else {
        return;
    };

    // Nothing to rewrite: the native schema is already the shape a client
    // receives, so leave it (and its root-level `$defs`) exactly as generated.
    let is_object_root = native.get("type").and_then(Value::as_str) == Some("object");
    if is_object_root {
        return;
    }

    let mut inner = Value::Object((*native).clone());
    let mut defs = Map::new();
    detach_schema_document_keys(&mut inner, &mut defs);

    let payload = json!({
        "type": "object",
        "properties": { "result": inner },
        "required": ["result"],
    });

    if let Value::Object(mut schema) = payload {
        // `$defs` came off a document that is now a branch; put it back at the
        // root so every `#/$defs/...` reference still resolves.
        if !defs.is_empty() {
            schema.insert("$defs".to_string(), Value::Object(defs));
        }
        tool.output_schema = Some(Arc::new(schema));
    }
}

/// Static resources served by the supervisor.
fn resources() -> Vec<Resource> {
    [
        (
            "ida://idb/metadata",
            "idb_metadata_resource",
            "IDB file metadata (path, arch, base address, size, hashes)",
        ),
        (
            "ida://idb/segments",
            "idb_segments_resource",
            "All memory segments with permissions",
        ),
        (
            "ida://idb/entrypoints",
            "idb_entrypoints_resource",
            "Entry points (main, TLS callbacks, etc.)",
        ),
        (
            "ida://cursor",
            "cursor_resource",
            "Current cursor position and function (always empty in headless mode)",
        ),
        (
            "ida://selection",
            "selection_resource",
            "Current selection range (always empty in headless mode)",
        ),
        ("ida://types", "types_resource", "All local types"),
        ("ida://structs", "structs_resource", "All structures/unions"),
        (
            "ida://databases",
            "databases_resource",
            "Open database sessions.",
        ),
    ]
    .into_iter()
    .map(|(uri, name, description)| {
        Resource::new(uri, name)
            .with_description(description)
            .with_mime_type("application/json")
    })
    .collect()
}

/// Parameterized resources served by the supervisor.
fn resource_templates() -> Vec<ResourceTemplate> {
    [
        (
            "ida://struct/{name}",
            "struct_name_resource",
            "Structure definition with fields",
        ),
        (
            "ida://import/{name}",
            "import_name_resource",
            "Import details by name",
        ),
        (
            "ida://export/{name}",
            "export_name_resource",
            "Export details by name",
        ),
        (
            "ida://xrefs/from/{addr}",
            "xrefs_from_resource",
            "Cross-references from an address",
        ),
    ]
    .into_iter()
    .map(|(uri_template, name, description)| {
        ResourceTemplate::new(uri_template, name)
            .with_description(description)
            .with_mime_type("application/json")
    })
    .collect()
}

/// Splices the session selector into a native tool's input schema. Native
/// tools address "the database this worker has open"; supervisor clients must
/// say which session they mean.
fn inject_database_argument(tool: &mut Tool) -> Result<(), String> {
    let schema = Arc::make_mut(&mut tool.input_schema);
    let properties = schema
        .entry("properties".to_string())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("tool {} inputSchema.properties is not an object", tool.name))?;
    properties.entry("database".to_string()).or_insert_with(|| {
        json!({
            "type": "string",
            "description": "Session ID returned by idb_open. Use idb_list to enumerate open sessions."
        })
    });

    let required = schema
        .entry("required".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| format!("tool {} inputSchema.required is not an array", tool.name))?;
    if !required
        .iter()
        .any(|value| value.as_str() == Some("database"))
    {
        required.push(Value::String("database".to_string()));
    }
    Ok(())
}

/// Wrap one of this server's own answers as a `CallToolResult`.
///
/// Only the session tools and the error arms come through here; a worker's
/// answer is forwarded as it was built. The one transformation is the `{result:
/// …}` wrapper for a non-object payload, which is what
/// `adapt_output_schema_for_supervisor` publishes.
fn tool_result(value: Value, is_error: bool) -> CallToolResult {
    let text = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    let structured = match &value {
        Value::Object(_) => value.clone(),
        _ => json!({"result": value}),
    };
    let mut result = if is_error {
        CallToolResult::error(vec![Content::text(text)])
    } else {
        CallToolResult::success(vec![Content::text(text)])
    };
    result.structured_content = (!is_error).then_some(structured);
    result
}

fn management_tool_result(result: Result<Value, String>) -> CallToolResult {
    match result {
        Ok(value) => tool_result(value, false),
        Err(error) => tool_result(json!({"error": error}), true),
    }
}

fn disabled_tool_message(name: &str) -> String {
    format!(
        "tool '{name}' is disabled by current filter \
         (--toolsets/--tools/--exclude-tools/--read-only)"
    )
}

fn unknown_tool_message(name: &str) -> String {
    if SUPERVISOR_OWNED_LIFECYCLE.contains(&name) {
        return format!(
            "Tool '{name}' is not routable: database lifecycle is owned by the supervisor. \
             Use idb_open / idb_list / idb_close."
        );
    }
    format!("Unknown tool '{name}'")
}

fn default_open_mode() -> String {
    "prefer_headless".to_string()
}

fn default_true() -> bool {
    true
}

fn default_idle_ttl() -> u64 {
    600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_required_database_argument() {
        let mut tool = catalog::native_tool("decompile").expect("decompile tool");

        inject_database_argument(&mut tool).expect("database injection");

        assert_eq!(
            tool.input_schema["properties"]["database"]["type"],
            "string"
        );
        assert!(tool.input_schema["required"]
            .as_array()
            .expect("required array")
            .iter()
            .any(|item| item == "database"));
    }

    #[test]
    fn advertised_catalog_is_the_native_surface_plus_session_tools() {
        let safe = SupervisorServer::advertised_tools(false).expect("safe catalog");
        let unsafe_catalog = SupervisorServer::advertised_tools(true).expect("unsafe catalog");
        let names = safe
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();

        assert_eq!(
            unsafe_catalog.len(),
            catalog::native_tool_names().count() - SUPERVISOR_OWNED_LIFECYCLE.len()
                + SESSION_TOOLS.len()
        );
        assert_eq!(safe.len(), unsafe_catalog.len() - UNSAFE_TOOLS.len());
        for lifecycle in SESSION_TOOLS {
            assert!(names.contains(lifecycle), "missing {lifecycle}");
        }
        for owned in SUPERVISOR_OWNED_LIFECYCLE {
            assert!(!names.contains(owned), "leaked worker-local {owned}");
        }
        for unsafe_name in UNSAFE_TOOLS {
            assert!(!names.contains(unsafe_name), "leaked unsafe {unsafe_name}");
        }
    }

    #[test]
    fn every_routed_tool_requires_a_database_selector() {
        for tool in SupervisorServer::advertised_tools(true).expect("catalog") {
            if SESSION_TOOLS.contains(&tool.name.as_ref()) {
                continue;
            }
            assert!(
                tool.input_schema["required"]
                    .as_array()
                    .is_some_and(|required| required.iter().any(|item| item == "database")),
                "{} does not require a database selector",
                tool.name
            );
        }
    }

    fn test_supervisor() -> SupervisorServer {
        let pool = crate::ida::pool::WorkerPool::new(crate::ida::pool::WorkerPoolConfig {
            max_workers: 1,
            min_workers: 0,
            worker_idle_timeout: std::time::Duration::from_secs(300),
            worker_op_timeout: std::time::Duration::from_secs(600),
            exe_path: std::path::PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        });
        SupervisorServer::new(
            SessionManager::new(pool),
            false,
            Arc::new(ToolPolicy::unrestricted()),
        )
    }

    #[tokio::test]
    async fn server_health_unknown_database_is_an_error() {
        let server = test_supervisor();
        let mut arguments = Map::new();
        arguments.insert("database".to_string(), json!("missing"));
        let error = server
            .call_management("server_health", arguments, CancellationToken::new())
            .await
            .expect_err("unknown database");
        assert!(error.contains("Unknown database session"), "{error}");
    }

    #[tokio::test]
    async fn server_health_without_database_lists_sessions() {
        let server = test_supervisor();
        let value = server
            .call_management("server_health", Map::new(), CancellationToken::new())
            .await
            .expect("health");
        assert_eq!(value["count"], 0);
        assert_eq!(value["sessions"], json!([]));
    }

    #[test]
    fn session_tool_failure_is_a_tool_error() {
        let result = management_tool_result(Err("missing input_path".to_string()));
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
        let text = result
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|text| text.text.as_str())
            .expect("text content");
        let value: Value = serde_json::from_str(text).expect("json error envelope");
        assert!(value.get("error").and_then(Value::as_str).is_some());
    }

    #[tokio::test]
    async fn cancelled_management_call_stops_before_worker_start() {
        let server = test_supervisor();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut arguments = Map::new();
        arguments.insert(
            "input_path".to_string(),
            json!(std::env::current_exe().expect("current test executable")),
        );

        let error = server
            .call_management("idb_open", arguments, cancel)
            .await
            .expect_err("cancelled open must not spawn a worker");

        assert_eq!(error, "cancelled idb_open before it started");
    }

    #[tokio::test]
    async fn cancelled_worker_call_stops_before_session_lookup() {
        let server = test_supervisor();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let mut arguments = Map::new();
        arguments.insert("database".to_string(), json!("missing"));

        let error = server
            .call_worker("analysis_status", arguments, cancel)
            .await
            .expect_err("cancelled call must not wait for a worker");

        assert_eq!(error, "cancelled analysis_status before it started");
    }
}
