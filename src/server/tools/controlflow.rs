#[vibrev_tool_router(
    router = controlflow_router,
    vis = "pub(crate)",
    defs = "controlflow_defs",
    cli = "controlflow_cli",
    call = "controlflow_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "Get basic blocks of a function (control flow graph nodes). \
        Always answers {results, analysis_coverage} with one entry per address, \
        even for a single address.",
        output = "responses::BasicBlocksOutput",
        title = "Control-flow graph nodes",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn basic_blocks(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: basic_blocks");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let single = addrs.len() == 1;
        let coverage = self.analysis_coverage().await;

        let mut results = Vec::new();
        for addr in addrs {
            match self.worker.basic_blocks(addr).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "basic_blocks": result
                })),
                // One address asked about, one address that failed: the call
                // failed. Keeping that an `isError` result rather than a
                // success carrying an error entry is what `ida::remote`'s
                // child-process classifier reads.
                Err(e) if single => return Ok(e.to_tool_result()),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(structured_with_coverage(
            &json!({ "results": results }),
            &coverage,
            "basic_blocks",
        ))
    }

    #[vibrev_tool(
        description = "Get functions called BY a function (callees/children in call graph). \
        Always answers {results, analysis_coverage} with one entry per address, \
        even for a single address.",
        output = "responses::CalleesOutput",
        title = "Functions this one calls",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn callees(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callees");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let single = addrs.len() == 1;
        let coverage = self.analysis_coverage().await;

        let mut results = Vec::new();
        for addr in addrs {
            match self.worker.callees(addr).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "callees": result
                })),
                Err(e) if single => return Ok(e.to_tool_result()),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(structured_with_coverage(
            &json!({ "results": results }),
            &coverage,
            "callees",
        ))
    }

    #[vibrev_tool(
        description = "Get functions that CALL a function (callers/parents in call graph). \
        Always answers {results, analysis_coverage} with one entry per address, \
        even for a single address.",
        output = "responses::CallersOutput",
        title = "Functions calling this one",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn callers(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callers");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let single = addrs.len() == 1;
        let coverage = self.analysis_coverage().await;

        let mut results = Vec::new();
        for addr in addrs {
            match self.worker.callers(addr).await {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "callers": result
                })),
                Err(e) if single => return Ok(e.to_tool_result()),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(structured_with_coverage(
            &json!({ "results": results }),
            &coverage,
            "callers",
        ))
    }

    #[vibrev_tool(
        description = "Find paths between two addresses (CFG)",
        output = "responses::FindPathsOutput",
        title = "Control-flow paths between two points",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "start,end")
    )]
    #[instrument(skip_all)]
    async fn find_paths(
        &self,
        Parameters(req): Parameters<FindPathsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_paths");
        let start = match req.start.to_single() {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let end = match req.end.to_single() {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_paths = try_param!(parse_optional_unsigned::<usize>(req.max_paths, "max_paths"))
            .unwrap_or(8)
            .min(128);
        let max_depth = try_param!(parse_optional_unsigned::<usize>(req.max_depth, "max_depth"))
            .unwrap_or(64)
            .min(2048);

        let coverage = self.analysis_coverage().await;
        match self
            .worker
            .find_paths(start, end, max_paths, max_depth)
            .await
        {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "find_paths")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Build a callgraph rooted at an address",
        output = "responses::CallGraphOutput",
        title = "Call graph around a root",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "roots")
    )]
    #[instrument(skip_all)]
    async fn callgraph(
        &self,
        Parameters(req): Parameters<CallGraphRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: callgraph");
        let roots = match req.roots.to_addresses() {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_depth = try_param!(parse_optional_unsigned::<usize>(req.max_depth, "max_depth"))
            .unwrap_or(2)
            .min(16);
        let max_nodes = try_param!(parse_optional_unsigned::<usize>(req.max_nodes, "max_nodes"))
            .unwrap_or(256)
            .min(10000);

        let coverage = self.analysis_coverage().await;
        if roots.len() == 1 {
            match self.worker.callgraph(roots[0], max_depth, max_nodes).await {
                Ok(result) => Ok(structured_with_coverage(&result, &coverage, "callgraph")),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for root in roots {
                match self.worker.callgraph(root, max_depth, max_nodes).await {
                    Ok(result) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "callgraph": result
                    })),
                    Err(e) => results.push(json!({
                        "root": format!("{:#x}", root),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_with_coverage(
                &json!({ "results": results }),
                &coverage,
                "callgraph",
            ))
        }
    }
}
