#[vibrev_tool_router(
    router = metadata_router,
    vis = "pub(crate)",
    defs = "metadata_defs",
    cli = "metadata_cli",
    call = "metadata_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "Get address context (segment, function, nearest symbol)",
        output = "responses::AddressInfo",
        title = "What lives at an address",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn addr_info(
        &self,
        Parameters(req): Parameters<AddrInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let coverage = self.analysis_coverage().await;
        match self
            .worker
            .addr_info(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(structured_with_coverage(&info, &coverage, "addr_info")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "List all segments in the database with their permissions and types",
        output = "Vec<responses::SegmentInfo>",
        title = "Memory layout",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all)]
    async fn segments(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: segments");
        match self.worker.segments().await {
            Ok(result) => Ok(structured_value(&result, "segments")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "List imports (external symbols) with pagination. \
        Answers {imports, total, next_offset, analysis_coverage}: one page plus the full count.",
        output = "responses::ImportListOutput",
        title = "External symbol table",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn imports(
        &self,
        Parameters(req): Parameters<ImportsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: imports");
        let query = try_param!(req.resolve_query());

        let coverage = self.analysis_coverage().await;
        match self.worker.imports(query).await {
            // The worker's result is the response: `{imports, total,
            // next_offset}`. Passing it through whole keeps the two fields
            // that say whether this page was the whole answer.
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "imports")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "List exports/names (public symbols) with pagination. \
        Answers {exports, total, next_offset, analysis_coverage}: one page plus the full count.",
        output = "responses::ExportListOutput",
        title = "Public symbol table",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn exports(
        &self,
        Parameters(req): Parameters<ExportsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: exports");
        let query = try_param!(req.resolve_query());

        let coverage = self.analysis_coverage().await;
        match self.worker.exports(query).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "exports")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get entry point addresses of the binary",
        output = "Vec<String>",
        title = "Program entry points",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all)]
    async fn entrypoints(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: entrypoints");
        match self.worker.entrypoints().await {
            Ok(result) => Ok(structured_value(&result, "entrypoints")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}
