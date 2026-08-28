#[tool_handler(router = self.tool_mux)]
impl ServerHandler for IdaMcpServer {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        supported_protocol_versions()
    }

    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tasks()
                .build(),
        )
        .with_instructions(self.instructions());
        // `ServerInfo::new` defaults to `Implementation::from_build_env()`,
        // which expands `env!("CARGO_CRATE_NAME")` in rmcp's compilation unit
        // and reports "rmcp" at rmcp's version. Report who we actually are.
        info.server_info = crate::server_implementation();
        info
    }

    // The `tasks/*` verbs are `vibrev_kit::tasks::TaskHost`'s, which this
    // server implements by naming its registry and its owner rule. None of the
    // three is async — the whole surface is a lookup under a mutex — so these
    // stay `async fn` only because `ServerHandler` asks for it.
    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        self.serve_get_task(request, &context.meta)
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.serve_update_task(request, &context.meta)
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.serve_cancel_task(request, &context.meta)
    }
}

/// Wrapper that sanitizes tool schemas by removing `$schema` fields.
///
/// Some MCP clients (like Claude Desktop) choke on the JSON Schema `$schema` field.
/// This wrapper intercepts `list_tools` to remove these fields while delegating
/// all other methods to the inner server.
pub struct SanitizedIdaServer<S> {
    inner: S,
    filter: Arc<ToolPolicy>,
}

impl<S> SanitizedIdaServer<S> {
    /// Wrap an inner server with no filtering. Convenience for paths
    /// that don't read CLI/env (e.g. tests).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            filter: Arc::new(ToolPolicy::unrestricted()),
        }
    }

    /// Wrap with an explicit filter (built from CLI/env at startup).
    pub fn with_filter(inner: S, filter: Arc<ToolPolicy>) -> Self {
        Self { inner, filter }
    }
}

impl<S> std::ops::Deref for SanitizedIdaServer<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Display titles for the tools this process does *not* define with `#[tool]`.
///
/// Every native tool states its own `title` on its attribute — both the ones
/// the macro dispatches through `#[vibrev_tool]` and the few it structurally
/// cannot, on plain `#[rmcp::tool]` — so what is left here is the
/// supervisor's session lifecycle, which is built name-first out of hand-written
/// `Tool` structs and has no attribute to carry it.
///
/// Keeping this table down to those four is the point: a lookup keyed on a name,
/// applied thousands of lines from the tool it describes, has nothing but a test
/// to notice when the two disagree. `every_tool_has_a_distinct_title` in
/// `tests/tool_surface.rs` still fails when a tool has no title, but for the
/// native surface it cannot fail *here* — a tool without one does not compile.
///
/// The MCP spec wants `title` to be a short label a user interface can show in
/// place of the machine name, so these deliberately do *not* restate the tool
/// name and do *not* repeat the first sentence of the description: the three
/// fields should tell a reader three different things (what to call it, what
/// it is, what it does).
pub(crate) fn tool_title_for(name: &str) -> Option<&'static str> {
    Some(match name {
        // Supervisor session lifecycle. Implemented by the supervisor, not by a
        // `#[tool]`, and read back by `supervisor::server::session_tools`.
        "idb_open" => "Start an analysis session",
        "idb_list" => "Open analysis sessions",
        "idb_close" => "End an analysis session",
        "server_health" => "Session occupancy",
        _ => return None,
    })
}

/// Safety annotations for the tools this process does *not* define with `#[tool]`.
///
/// Same story as [`tool_title_for`]: every native tool declares its own, so what
/// remains is the supervisor's session lifecycle. The fallback arm never claims
/// `read_only` — handing that to a name nobody recognises is the most dangerous
/// possible default for a table that silently covers every tool nobody has
/// thought about.
fn tool_annotations_for(name: &str) -> ToolAnnotations {
    match name {
        // `idb_open` leases a worker process and mutates the supervisor's
        // session table, `idb_close` tears one down (and by default writes the
        // database back), `idb_list` / `server_health` only read that table.
        // None of them reach outside this process.
        "idb_open" => ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(false),
        "idb_list" => ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
        "idb_close" => ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(true)
            .open_world(false),
        "server_health" => ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
        // Unreachable for the native surface, which declares its own. Kept
        // conservative rather than convenient: a tool that reaches this arm is
        // one nobody described, and calling it read-only would be a guess in the
        // direction that gets things deleted.
        _ => ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .open_world(false),
    }
}

/// Bridge `tool_catalog`'s declared parameter to the catalog's own enum.
///
/// Two enums for one concept is not ideal, but the alternative is worse in a
/// specific way: `catalog::ToolCategory` is also a *response* type (it is what
/// `tool_catalog` echoes back and what `--toolsets` parses), and giving it the
/// tolerant `Deserialize` a request parameter wants would change how those
/// parse too. The mapping is exhaustive in both directions, so a new category
/// fails to compile here rather than silently dropping out of the filter.
fn catalog_category(category: requests::CatalogCategory) -> ToolCategory {
    use requests::CatalogCategory as C;
    match category {
        C::Core => ToolCategory::Core,
        C::Functions => ToolCategory::Functions,
        C::Disassembly => ToolCategory::Disassembly,
        C::Decompile => ToolCategory::Decompile,
        C::Xrefs => ToolCategory::Xrefs,
        C::ControlFlow => ToolCategory::ControlFlow,
        C::Memory => ToolCategory::Memory,
        C::Search => ToolCategory::Search,
        C::Metadata => ToolCategory::Metadata,
        C::Types => ToolCategory::Types,
        C::Editing => ToolCategory::Editing,
        C::Scripting => ToolCategory::Scripting,
    }
}

/// Fill in title and annotations for a tool that did not declare its own.
///
/// For the native surface this is a no-op, and the compiler is what keeps it
/// that way: `#[vibrev_tool]` refuses to expand without `title` and
/// `annotations(read_only = ..)`, and the five tools it cannot dispatch carry the
/// same fields on plain `#[rmcp::tool]`. The name-keyed lookups this consults
/// cover only the supervisor's session tools, which are hand-built `Tool` structs
/// with no attribute to declare anything on.
///
/// A declared value wins over the table: these arms only fill in what an
/// attribute left unset, so `tools/list` never shifts under a tool that states
/// its own.
fn set_tool_metadata(tool: &mut Tool) {
    if tool.annotations.is_none() {
        tool.annotations = Some(tool_annotations_for(&tool.name));
    }
    if tool.title.is_none()
        && let Some(title) = tool_title_for(&tool.name)
    {
        tool.title = Some(title.to_string());
    }
}

/// Attach the display title and safety annotations a tool advertises on
/// `tools/list`. Used by the native catalog and by the supervisor's own
/// session tools so both faces read from the same tables.
pub(crate) fn apply_tool_metadata(mut tool: Tool) -> Tool {
    set_tool_metadata(&mut tool);
    tool
}

/// Bring each advertised tool to the shape this workspace publishes: schemas
/// normalized, then the title and annotations filled in for anything that did
/// not declare its own.
///
/// The normalizing is [`vibrev_kit::schema::normalize_tool`] so that this engine
/// and `bn-headless-mcp` describe the same parameter the same way — two engines
/// meant to feel alike must not advertise one `Option<u32>` in two different
/// structures. The same code runs inside `#[vibrev_tool]`, so for the derived
/// tools this pass changes nothing. It earns its keep on the few on plain
/// `#[rmcp::tool]` and on the supervisor's hand-built session tools.
fn normalize_tool_schemas(result: &mut ListToolsResult) {
    for tool in &mut result.tools {
        vibrev_kit::schema::normalize_tool(tool);
        set_tool_metadata(tool);
    }
}

/// Error message for a filter-rejected tool/call. Centralized so the
/// dispatch and tool_help paths return identical wording.
fn disabled_tool_message(name: &str) -> String {
    format!(
        "tool '{name}' is disabled by current filter \
         (--toolsets/--tools/--exclude-tools/--read-only); \
         call tool_catalog to see enabled tools"
    )
}

/// Only the two methods that sanitize. Everything else — the tasks face, and the
/// eighteen methods this impl never mentions — passes through because
/// [`Decorator`] has no other default.
///
/// `discover` and `initialize` are deliberately left unoverridden so the trait
/// defaults bind `self.get_info()` rather than the inner's: see
/// `vibrev_kit::decorate`, where both republish what this wrapper's `get_info`
/// says over the inner server's answer.
impl<S: ServerHandler + Send + Sync> Decorator for SanitizedIdaServer<S> {
    type Inner = S;

    fn inner(&self) -> &S {
        &self.inner
    }

    async fn list_tools(
        &self,
        params: Option<PaginatedRequestParams>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self.inner.list_tools(params, ctx).await?;
        if self.filter.is_active() {
            result
                .tools
                .retain(|tool| self.filter.allows(&tool.name));
        }
        normalize_tool_schemas(&mut result);
        Ok(result)
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if self.filter.is_active() && !self.filter.allows(&params.name) {
            return Err(McpError::invalid_params(
                disabled_tool_message(&params.name),
                None,
            ));
        }
        self.inner.call_tool(params, ctx).await
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        if self.filter.is_active() && !self.filter.allows(name) {
            return None;
        }
        self.inner.get_tool(name).map(|mut tool| {
            vibrev_kit::schema::normalize_tool(&mut tool);
            apply_tool_metadata(tool)
        })
    }
}

vibrev_kit::decorated_handler!(SanitizedIdaServer<S>, generic S: ServerHandler + Send + Sync);
