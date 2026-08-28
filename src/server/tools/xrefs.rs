#[vibrev_tool_router(
    router = xrefs_router,
    vis = "pub(crate)",
    defs = "xrefs_defs",
    cli = "xrefs_cli",
    call = "xrefs_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "Find strings and return xrefs to each match.",
        output = "responses::StringXrefsResult",
        title = "References to matching strings",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "query")
    )]
    async fn xrefs_to_string(
        &self,
        Parameters(req): Parameters<XrefsToStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let search = try_param!(req.resolve_search());
        let max_xrefs =
            try_param!(parse_optional_unsigned::<usize>(req.max_xrefs, "max_xrefs")).unwrap_or(64);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self
            .worker
            .xrefs_to_string(search, max_xrefs, timeout_secs)
            .await
        {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "xrefs_to_string",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get cross-references TO an address (who references this address). \
        Paginated (default limit 1000, max 10000); when truncated=true, pass next_offset back \
        as offset to page through high-frequency targets.",
        output = "responses::XRefsOutput",
        title = "Incoming references",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn xrefs_to(
        &self,
        Parameters(req): Parameters<XrefsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_to");
        self.xrefs_lookup(req, XrefDirection::To).await
    }

    #[vibrev_tool(
        description = "Get cross-references FROM an address (what this address references). \
        Paginated (default limit 1000, max 10000); when truncated=true, pass next_offset back \
        as offset to page through the remaining references.",
        output = "responses::XRefsOutput",
        title = "Outgoing references",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn xrefs_from(
        &self,
        Parameters(req): Parameters<XrefsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xrefs_from");
        self.xrefs_lookup(req, XrefDirection::From).await
    }

    #[vibrev_tool(
        description = "Compute xref matrix for a set of addresses",
        output = "responses::XrefMatrixOutput",
        title = "Reference matrix across addresses",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "addrs")
    )]
    #[instrument(skip_all)]
    async fn xref_matrix(
        &self,
        Parameters(req): Parameters<XrefMatrixRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: xref_matrix");
        let addrs = match req.addrs.to_addresses() {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let coverage = self.analysis_coverage().await;
        match self.worker.xref_matrix(addrs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "xref_matrix")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get xrefs to a struct field. \
        Ordinal and name are mutually exclusive; passing both is rejected.",
        output = "responses::XrefsToFieldResult",
        title = "References to a struct field",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn xrefs_to_field(
        &self,
        Parameters(req): Parameters<XrefsToFieldRequest>,
    ) -> Result<CallToolResult, McpError> {
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(1000)
            .min(10000);
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));
        let member_index = try_param!(parse_optional_unsigned::<u32>(
            req.member_index,
            "member_index"
        ));
        let coverage = self.analysis_coverage().await;
        match self
            .worker
            .xrefs_to_field(
                ordinal,
                req.name.clone(),
                member_index,
                req.member_name.clone(),
                limit,
            )
            .await
        {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "xrefs_to_field",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}
