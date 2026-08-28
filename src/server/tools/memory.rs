#[vibrev_tool_router(
    router = memory_router,
    vis = "pub(crate)",
    defs = "memory_defs",
    cli = "memory_cli",
    call = "memory_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "List strings in the database with pagination and optional filter.",
        output = "responses::StringListResult",
        title = "Browse extracted strings",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn strings(
        &self,
        Parameters(req): Parameters<StringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: strings");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        let coverage = self.analysis_coverage().await;
        match self.worker.strings(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "strings")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Find strings matching a query (supports exact/case-insensitive options).",
        output = "responses::StringListResult",
        title = "String lookup by text",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "query")
    )]
    async fn find_string(
        &self,
        Parameters(req): Parameters<FindStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        let search = try_param!(req.resolve_search());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.find_string(search, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "find_string")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Read raw bytes from an address as hex string",
        output = "responses::GetBytesOutput",
        title = "Raw bytes as hex",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(size = req.size))]
    async fn get_bytes(
        &self,
        Parameters(req): Parameters<GetBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_bytes");
        let size = try_param!(parse_optional_unsigned::<usize>(req.size, "size"))
            .unwrap_or(256)
            .min(0x10000);
        if let Some(addr_value) = req.address.as_ref() {
            let addrs = match addr_value.to_addresses() {
                Ok(a) => a,
                Err(e) => return Ok(e.to_tool_result()),
            };

            if addrs.len() == 1 {
                match self.worker.get_bytes(Some(addrs[0]), None, 0, size).await {
                    Ok(result) => Ok(structured_value(&result, "get_bytes")),
                    Err(e) => Ok(e.to_tool_result()),
                }
            } else {
                let mut results = Vec::new();
                for addr in addrs {
                    match self.worker.get_bytes(Some(addr), None, 0, size).await {
                        Ok(result) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "bytes": result
                        })),
                        Err(e) => results.push(json!({
                            "address": format!("{:#x}", addr),
                            "error": e.to_string()
                        })),
                    }
                }
                Ok(structured_json(json!({ "results": results })))
            }
        } else if let Some(name) = req.target_name.as_ref() {
            let offset = req.offset.unwrap_or(0);
            match self
                .worker
                .get_bytes(None, Some(name.clone()), offset, size)
                .await
            {
                Ok(result) => Ok(structured_value(&result, "get_bytes")),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            Ok(ToolError::InvalidParams("address or name required".to_string()).to_tool_result())
        }
    }

    #[vibrev_tool(
        description = "List global names (non-function symbols).",
        output = "responses::GlobalListResult",
        title = "Browse non-function symbols",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn list_globals(
        &self,
        Parameters(req): Parameters<ListGlobalsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: list_globals");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.list_globals(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "list_globals")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Analyze strings with xrefs (ida-pro-mcp compatibility).",
        output = "responses::AnalyzeStringsResult",
        title = "Strings with their references",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, query = ?req.query))]
    async fn analyze_strings(
        &self,
        Parameters(req): Parameters<AnalyzeStringsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_strings");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self
            .worker
            .analyze_strings(query, timeout_secs)
            .await
        {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "analyze_strings",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Find byte patterns (ida-pro-mcp compatibility).",
        output = "responses::FindBytesOutput",
        title = "Byte-pattern scan",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "patterns")
    )]
    #[instrument(skip_all)]
    async fn find_bytes(
        &self,
        Parameters(req): Parameters<FindBytesRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: find_bytes");
        let patterns = match Self::value_to_strings(&req.patterns) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let worker_max_results = if matches!(self.mode, ServerMode::Worker) {
            try_param!(parse_optional_unsigned::<usize>(
                req.worker_max_results,
                "_worker_max_results"
            ))
            .map(|value| value.min(20000))
        } else {
            None
        };
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let response_limit = worker_max_results.unwrap_or(limit);
        let max_results = bounded_scan_ceiling(offset, limit, worker_max_results);
        let mut results = Vec::new();

        for pattern in patterns {
            match self
                .worker
                .find_bytes(pattern.clone(), max_results, timeout_secs)
                .await
            {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let page =
                        paginate_bounded_matches(matches, offset, response_limit, max_results);
                    let mut entry = json!({
                        "pattern": pattern,
                        "matches": page.matches,
                        "total": page.total,
                        "total_is_lower_bound": page.total_is_lower_bound,
                    });
                    if let Some(next) = page.next_offset {
                        entry["next_offset"] = json!(next);
                    }
                    results.push(entry);
                }
                Err(e) => results.push(json!({
                    "pattern": pattern,
                    "error": e.to_string()
                })),
            }
        }

        Ok(structured_json(json!({ "results": results })))
    }

    #[vibrev_tool(
        description = "Search for text or immediates (ida-pro-mcp compatibility).",
        output = "responses::SearchOutput",
        title = "Text and immediate scan",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "targets")
    )]
    #[instrument(skip_all)]
    async fn search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: search");
        let targets = match Self::value_to_strings(&req.targets) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(100)
            .min(10000);
        let offset =
            try_param!(parse_optional_unsigned::<usize>(req.offset, "offset")).unwrap_or(0);
        let worker_max_results = if matches!(self.mode, ServerMode::Worker) {
            try_param!(parse_optional_unsigned::<usize>(
                req.worker_max_results,
                "_worker_max_results"
            ))
            .map(|value| value.min(20000))
        } else {
            None
        };
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let kind = req.kind.unwrap_or(requests::SearchKind::Auto);
        let scope = try_param!(req.resolve_scope());
        let code_only = req.code_only.unwrap_or(false);
        let coverage = self.analysis_coverage().await;

        let response_limit = worker_max_results.unwrap_or(limit);
        let max_results = bounded_scan_ceiling(offset, limit, worker_max_results);
        let mut results = Vec::new();
        for target in targets {
            let search_result = if kind == requests::SearchKind::Imm {
                match Self::parse_address(&target) {
                    Ok(val) => {
                        self.worker
                            .search_imm(val, max_results, scope.clone(), code_only, timeout_secs)
                            .await
                    }
                    Err(e) => {
                        results.push(json!({
                            "target": target,
                            "error": e.to_string()
                        }));
                        continue;
                    }
                }
            } else if kind == requests::SearchKind::Text {
                self.worker
                    .search_text(
                        target.clone(),
                        max_results,
                        scope.clone(),
                        code_only,
                        timeout_secs,
                    )
                    .await
            } else if let Ok(val) = Self::parse_address(&target) {
                self.worker
                    .search_imm(val, max_results, scope.clone(), code_only, timeout_secs)
                    .await
            } else {
                self.worker
                    .search_text(
                        target.clone(),
                        max_results,
                        scope.clone(),
                        code_only,
                        timeout_secs,
                    )
                    .await
            };

            match search_result {
                Ok(value) => {
                    let matches = value
                        .get("matches")
                        .and_then(|m| m.as_array())
                        .cloned()
                        .unwrap_or_default();
                    let page =
                        paginate_bounded_matches(matches, offset, response_limit, max_results);
                    let mut entry = json!({
                        "target": target,
                        "matches": page.matches,
                        "total": page.total,
                        "total_is_lower_bound": page.total_is_lower_bound,
                    });
                    if let Some(next) = page.next_offset {
                        entry["next_offset"] = json!(next);
                    }
                    results.push(entry);
                }
                Err(e) => results.push(json!({
                    "target": target,
                    "error": e.to_string()
                })),
            }
        }

        Ok(structured_with_coverage(
            &json!({ "results": results }),
            &coverage,
            "search",
        ))
    }

    #[vibrev_tool(
        description = "Read u8 values at address(es)",
        output = "responses::GetIntOutput",
        title = "8-bit reads",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn get_u8(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 1).await
    }

    #[vibrev_tool(
        description = "Read u16 values at address(es)",
        output = "responses::GetIntOutput",
        title = "16-bit reads",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn get_u16(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 2).await
    }

    #[vibrev_tool(
        description = "Read u32 values at address(es)",
        output = "responses::GetIntOutput",
        title = "32-bit reads",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn get_u32(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 4).await
    }

    #[vibrev_tool(
        description = "Read u64 values at address(es)",
        output = "responses::GetIntOutput",
        title = "64-bit reads",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn get_u64(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        get_int_values(&self.worker, req.address, 8).await
    }

    #[vibrev_tool(
        description = "Build a byte signature that identifies an address. Grows the pattern one \
                       instruction at a time, wildcarding operands, until it matches exactly one \
                       place in the database — then reports whether it is really unique. Pass \
                       'end' to cover a fixed range instead.",
        output = "responses::MakeSignatureOutput",
        title = "Unique byte signature",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn make_signature(
        &self,
        Parameters(req): Parameters<MakeSignatureRequest>,
    ) -> Result<CallToolResult, McpError> {
        let requests = try_param!(req.resolve());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        if let [single] = requests.as_slice() {
            return match self
                .worker
                .make_signature(single.clone(), timeout_secs)
                .await
            {
                Ok(result) => Ok(structured_value(&result, "make_signature")),
                Err(e) => Ok(e.to_tool_result()),
            };
        }

        let mut results = Vec::with_capacity(requests.len());
        for request in requests {
            let address = format!("{:#x}", request.address);
            match self.worker.make_signature(request, timeout_secs).await {
                Ok(result) => results.push(result),
                Err(e) => results.push(json!({ "address": address, "error": e.to_string() })),
            }
        }
        Ok(structured_json(json!({ "results": results })))
    }

    #[vibrev_tool(
        description = "Read an integer of any width, signedness and byte order. Unlike \
                       get_u8/get_u16/get_u32/get_u64, this reads signed types and can \
                       override the database's byte order (e.g. ty='i32', ty='u16be').",
        output = "responses::GetTypedIntOutput",
        title = "Typed integer read",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(ty = %req.ty))]
    async fn get_int(
        &self,
        Parameters(req): Parameters<GetIntRequest>,
    ) -> Result<CallToolResult, McpError> {
        let spec = try_param!(req.ty.parse::<IntSpec>());
        get_typed_int_values(&self.worker, req.address, spec).await
    }

    #[vibrev_tool(
        description = "Write an integer of any width, signedness and byte order. The value is \
                       range-checked against the type, so a value that does not fit is an \
                       error rather than a silent truncation.",
        output = "responses::PutIntOutput",
        title = "Typed integer write",
        annotations(
            read_only = false,
            destructive = true,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(ty = %req.ty))]
    async fn put_int(
        &self,
        Parameters(req): Parameters<PutIntRequest>,
    ) -> Result<CallToolResult, McpError> {
        let spec = try_param!(req.ty.parse::<IntSpec>());
        let addr = try_param!(req.address.to_exactly_one("address"));
        let value = try_param!(parse_signed_value(&req.value));
        match self.worker.put_int(addr, spec, value).await {
            Ok(result) => Ok(structured_value(&result, "put_int")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Read string(s) at address(es)",
        output = "responses::GetStringOutput",
        title = "String stored at an address",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn get_string(
        &self,
        Parameters(req): Parameters<GetStringRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_string");
        let addrs = match req.address.to_addresses() {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let max_len = try_param!(parse_optional_unsigned::<usize>(req.max_len, "max_len"))
            .unwrap_or(256)
            .min(0x10000);

        if addrs.len() == 1 {
            match self.worker.get_string(addrs[0], max_len).await {
                Ok(result) => Ok(structured_value(&result, "get_string")),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for addr in addrs {
                match self.worker.get_string(addr, max_len).await {
                    Ok(result) => results.push(json!({
                        "address": format!("{:#x}", addr),
                        "string": result
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
        description = "Get global value(s) by name or address",
        output = "responses::GetGlobalValueOutput",
        title = "Value behind a global symbol",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "query")
    )]
    #[instrument(skip_all)]
    async fn get_global_value(
        &self,
        Parameters(req): Parameters<GetGlobalValueRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: get_global_value");
        let queries = match Self::value_to_strings(&req.query) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        if queries.len() == 1 {
            match self.worker.get_global_value(queries[0].clone()).await {
                Ok(result) => Ok(structured_value(&result, "get_global_value")),
                Err(e) => Ok(e.to_tool_result()),
            }
        } else {
            let mut results = Vec::new();
            for query in queries {
                match self.worker.get_global_value(query.clone()).await {
                    Ok(result) => results.push(json!({
                        "query": query,
                        "value": result
                    })),
                    Err(e) => results.push(json!({
                        "query": query,
                        "error": e.to_string()
                    })),
                }
            }
            Ok(structured_json(json!({ "results": results })))
        }
    }

    #[vibrev_tool(
        description = "Convert integers between bases",
        output = "responses::IntConvertOutput",
        title = "Integer base and byte-order converter",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "inputs", no_session)
    )]
    #[instrument(skip_all)]
    async fn int_convert(
        &self,
        Parameters(req): Parameters<IntConvertRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: int_convert");
        let inputs = match Self::value_to_strings(&req.inputs) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let mut results = Vec::new();
        for input in inputs {
            match Self::parse_address(&input) {
                Ok(value) => {
                    let le = value.to_le_bytes();
                    let be = value.to_be_bytes();
                    let le_trim = trim_bytes_le(&le);
                    let be_trim = trim_bytes_be(&be);
                    results.push(json!({
                        "input": input,
                        "value": value,
                        "dec": value.to_string(),
                        "hex": format!("0x{:x}", value),
                        "bin": format!("0b{:b}", value),
                        "bytes_le": hex_encode(&le_trim),
                        "bytes_be": hex_encode(&be_trim),
                        "ascii": bytes_to_ascii(&le_trim),
                    }));
                }
                Err(e) => results.push(json!({
                    "input": input,
                    "error": e.to_string()
                })),
            }
        }

        Ok(structured_json(json!({ "results": results })))
    }

    #[vibrev_tool(
        description = "Find instruction sequences by mnemonic. Scope the scan to one function, \
                       one segment, or an address range instead of the whole database.",
        output = "responses::InsnSearchOutput",
        title = "Mnemonic sequence scan",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "patterns")
    )]
    async fn find_insns(
        &self,
        Parameters(req): Parameters<FindInsnsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let scan = try_param!(req.resolve_scan());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.find_insns(scan, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "find_insns")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Find instruction operands. Scope the scan to one function, one segment, \
                       or an address range instead of the whole database.",
        output = "responses::InsnOperandSearchOutput",
        title = "Operand pattern scan",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "patterns")
    )]
    async fn find_insn_operands(
        &self,
        Parameters(req): Parameters<FindInsnOperandsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let scan = try_param!(req.resolve_scan());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.find_insn_operands(scan, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "find_insn_operands",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}
