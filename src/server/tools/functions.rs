#[vibrev_tool_router(
    router = functions_router,
    vis = "pub(crate)",
    defs = "functions_defs",
    cli = "functions_cli",
    call = "functions_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "List all functions in the database (paginated).",
        output = "responses::FunctionListResult",
        title = "Browse every function",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn list_functions(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_functions");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        let coverage = self.analysis_coverage().await;
        match self.worker.list_functions(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "list_functions",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "List functions (ida-pro-mcp compatible alias).",
        output = "responses::FunctionListResult",
        title = "Browse every function (alias)",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn list_funcs(
        &self,
        Parameters(req): Parameters<ListFunctionsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_funcs");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        let coverage = self.analysis_coverage().await;
        match self.worker.list_functions(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "list_funcs")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Resolve a function name to its address",
        output = "responses::FunctionInfo",
        title = "Function address by name",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "name")
    )]
    #[instrument(skip_all, fields(name = %req.name))]
    async fn resolve_function(
        &self,
        Parameters(req): Parameters<ResolveFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: resolve_function");
        match self.worker.resolve_function(&req.name).await {
            Ok(info) => Ok(structured_value(&info, "resolve_function")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get the function that contains an address",
        output = "responses::FunctionRangeInfo",
        title = "Enclosing function of an address",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn function_at(
        &self,
        Parameters(req): Parameters<FunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        match self
            .worker
            .function_at(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(info) => Ok(structured_value(&info, "function_at")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get disassembly at an address",
        output = "responses::DisasmOutput",
        title = "Instructions at an address",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address, count = req.count))]
    async fn disasm(
        &self,
        Parameters(req): Parameters<DisasmRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm");
        // Clamp instruction count
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(10)
            .min(1000);
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.disasm(addrs[0], count).await {
                // The text block stays the raw listing; `structuredContent`
                // carries the same listing keyed by the address it starts at.
                Ok(text) => Ok(structured_result(
                    text.clone(),
                    json!({ "address": format!("{:#x}", addrs[0]), "disasm": text }),
                )),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.disasm(addr, count).await {
                    Ok(text) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "disasm": text
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_json(json!({ "results": results })))
        }
    }

    #[vibrev_tool(
        description = "Get disassembly for a function by name",
        output = "responses::FunctionDisasmOutput",
        title = "Instructions of a named function",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "name")
    )]
    #[instrument(skip_all, fields(name = %req.name, count = req.count))]
    async fn disasm_by_name(
        &self,
        Parameters(req): Parameters<DisasmByNameRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: disasm_by_name");
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(10)
            .min(1000);

        match self.worker.disasm_by_name(&req.name, count).await {
            Ok(text) => Ok(structured_result(text.clone(), json!({ "disasm": text }))),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Disassemble the function containing an address",
        output = "responses::FunctionDisasmOutput",
        title = "Whole-function instruction listing",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn disasm_function_at(
        &self,
        Parameters(req): Parameters<DisasmFunctionAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let count = try_param!(parse_optional_unsigned::<usize>(req.count, "count"))
            .unwrap_or(200)
            .min(5000);
        match self
            .worker
            .disasm_function_at(addr, req.target_name.clone(), offset, count)
            .await
        {
            Ok(text) => Ok(structured_result(text.clone(), json!({ "disasm": text }))),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Decompile a function using Hex-Rays (if available)",
        output = "responses::DecompileOutput",
        title = "C pseudocode for a function",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address))]
    async fn decompile(
        &self,
        Parameters(req): Parameters<DecompileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: decompile");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if addrs.len() == 1 {
            match self.worker.decompile(addrs[0]).await {
                // Keep the C listing itself in the text block — a client that
                // renders `content` must not be handed escaped JSON instead.
                Ok(code) => Ok(structured_result(
                    code.clone(),
                    json!({ "address": format!("{:#x}", addrs[0]), "code": code }),
                )),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.decompile(addr).await {
                    Ok(code) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "decompile": code
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_json(json!({ "results": results })))
        }
    }

    #[vibrev_tool(
        description = "Get decompiled pseudocode at a specific address or address range. \
        Unlike 'decompile' which returns the full function, this returns only the statements \
        that correspond to the given address(es). Useful for getting pseudocode for a basic block \
        or specific instruction. If end_address is provided, returns statements covering the range.",
        output = "responses::PseudocodeAtOutput",
        title = "Pseudocode for one address range",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address, end_address = ?req.end_address))]
    async fn pseudocode_at(
        &self,
        Parameters(req): Parameters<PseudocodeAtRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: pseudocode_at");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let end_addr = if let Some(ref end_str) = req.end_address {
            match Self::parse_address(end_str) {
                Ok(a) => Some(a),
                Err(e) => return Ok(e.to_tool_result()),
            }
        } else {
            None
        };

        if addrs.len() == 1 {
            match self.worker.pseudocode_at(addrs[0], end_addr).await {
                Ok(result) => Ok(structured_json(result)),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.pseudocode_at(addr, end_addr).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "pseudocode": result
                    })),
                    Err(e) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_json(json!({ "results": results })))
        }
    }

    #[vibrev_tool(
        description = "Lookup functions by name or address (batch)",
        output = "responses::LookupFuncsOutput",
        title = "Batch function lookup",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "queries")
    )]
    #[instrument(skip_all)]
    async fn lookup_funcs(
        &self,
        Parameters(req): Parameters<LookupFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: lookup_funcs");
        let queries = match Self::value_to_strings(&req.queries) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.lookup_funcs(queries).await {
            Ok(result) => Ok(structured_value(&result, "lookup_funcs")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Export functions (ida-pro-mcp compatibility)",
        output = "responses::ExportFuncsOutput",
        title = "Bulk function export",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit))]
    async fn export_funcs(
        &self,
        Parameters(req): Parameters<ExportFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: export_funcs");
        let coverage = self.analysis_coverage().await;
        if let Some(addrs) = req.addrs {
            let queries = match Self::value_to_strings(&addrs) {
                Ok(v) => v,
                Err(e) => return Ok(e.to_tool_result()),
            };
            match self.worker.lookup_funcs(queries).await {
                Ok(result) => Ok(structured_with_coverage(&result, &coverage, "export_funcs")),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
                .unwrap_or(100)
                .min(10000);
            let offset =
                try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
            match self.worker.export_funcs(offset, limit).await {
                Ok(result) => Ok(structured_with_coverage(&result, &coverage, "export_funcs")),
                Err(e) => Ok(e.to_tool_result()),
            }
        }
    }
}
