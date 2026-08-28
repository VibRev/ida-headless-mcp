#[vibrev_tool_router(
    router = types_router,
    vis = "pub(crate)",
    defs = "types_defs",
    cli = "types_cli",
    call = "types_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "List local types",
        output = "responses::LocalTypeListResult",
        title = "Browse the local type library",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn local_types(
        &self,
        Parameters(req): Parameters<LocalTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.local_types(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "local_types")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Declare a type in the local type library. \
        A declaration IDA did not store answers isError=true; the error detail keeps IDA's code.",
        output = "responses::DeclareTypeOutput",
        title = "Add a local type",
        annotations(read_only = false, destructive = false, open_world = false),
        cli(positional = "decl")
    )]
    async fn declare_type(
        &self,
        Parameters(req): Parameters<DeclareTypeRequest>,
    ) -> Result<CallToolResult, McpError> {
        let relaxed = req.relaxed.unwrap_or(false);
        let replace = req.replace.unwrap_or(false);
        let multi = req.multi.unwrap_or(false);
        match self
            .worker
            .declare_type(req.decl.clone(), relaxed, replace, multi)
            .await
        {
            Ok(result) => match type_mutation_failure(&result) {
                Some(reason) => Ok(structured_failure(
                    &result,
                    "declare_type",
                    format!(
                        "declare_type did not store the declaration: {reason}. The local type \
                         library is unchanged; pass replace=true to overwrite an existing name, \
                         or relaxed=true for a declaration IDA parses strictly."
                    ),
                )),
                None => Ok(structured_value(&result, "declare_type")),
            },
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get stack frame info",
        output = "responses::FrameInfo",
        title = "Frame layout of a function",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    async fn stack_frame(
        &self,
        Parameters(req): Parameters<AddressRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.to_single() {
            Ok(addr) => addr,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self.worker.stack_frame(addr).await {
            Ok(result) => Ok(structured_value(&result, "stack_frame")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Declare a stack variable in a function frame. \
        A rejected declaration answers isError=true; the error detail keeps IDA's code.",
        output = "responses::StackVarResult",
        title = "Add a stack variable",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn declare_stack(
        &self,
        Parameters(req): Parameters<DeclareStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let relaxed = req.relaxed.unwrap_or(false);
        match self
            .worker
            .declare_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
                req.decl.clone(),
                relaxed,
            )
            .await
        {
            Ok(result) if result.code != 0 => {
                let message = format!(
                    "declare_stack did not define the stack variable: IDA returned code {} for \
                     frame offset {} of the function at {}. The frame is unchanged; read \
                     stack_frame to see its current members.",
                    result.code, result.offset, result.function
                );
                Ok(structured_failure(&result, "declare_stack", message))
            }
            Ok(result) => Ok(structured_value(&result, "declare_stack")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Delete a stack variable from a function frame. \
        A rejected deletion answers isError=true; the error detail keeps IDA's code.",
        output = "responses::StackVarResult",
        title = "Remove a stack variable",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn delete_stack(
        &self,
        Parameters(req): Parameters<DeleteStackRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .delete_stack(
                addr,
                req.target_name.clone(),
                req.offset,
                req.var_name.clone(),
            )
            .await
        {
            Ok(result) if result.code != 0 => {
                let message = format!(
                    "delete_stack did not delete the stack variable: IDA returned code {} for \
                     frame offset {} of the function at {}. The frame is unchanged; read \
                     stack_frame to see its current members.",
                    result.code, result.offset, result.function
                );
                Ok(structured_failure(&result, "delete_stack", message))
            }
            Ok(result) => Ok(structured_value(&result, "delete_stack")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "List structs in the database with pagination and optional filter.",
        output = "responses::StructListResult",
        title = "Browse structures and unions",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(offset = req.offset, limit = req.limit, filter = ?req.filter))]
    async fn structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: structs");
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        let coverage = self.analysis_coverage().await;
        match self.worker.structs(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(&result, &coverage, "structs")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Get info about a struct by ordinal or name. \
        Ordinal and name are mutually exclusive; passing both is rejected.",
        output = "responses::StructInfo",
        title = "Struct definition detail",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(ordinal = req.ordinal, name = ?req.name))]
    async fn struct_info(
        &self,
        Parameters(req): Parameters<StructInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: struct_info");
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));
        match self.worker.struct_info(ordinal, req.name).await {
            Ok(result) => Ok(structured_value(&result, "struct_info")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Read values of a struct instance at an address. \
        Always answers {results} with one entry per address, even for a single address. \
        Identify the layout by name, or by an ordinal read from structs/local_types in this \
        same session; passing both is rejected.",
        output = "responses::ReadStructOutput",
        title = "Struct instance values in memory",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = %req.address, ordinal = req.ordinal, name = ?req.name))]
    async fn read_struct(
        &self,
        Parameters(req): Parameters<ReadStructRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: read_struct");
        let addrs = match req.address.to_addresses() {
            Ok(a) => a,
            Err(e) => return Ok(e.to_tool_result()),
        };
        let ordinal = try_param!(parse_optional_unsigned::<u32>(req.ordinal, "ordinal"));
        let single = addrs.len() == 1;

        let mut results = Vec::new();
        for addr in addrs {
            match self
                .worker
                .read_struct(addr, ordinal, req.name.clone())
                .await
            {
                Ok(result) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "struct": result
                })),
                Err(e) if single => return Ok(e.to_tool_result()),
                Err(e) => results.push(json!({
                    "address": format!("{:#x}", addr),
                    "error": e.to_string()
                })),
            }
        }
        Ok(structured_json(json!({ "results": results })))
    }

    #[vibrev_tool(
        description = "Search structs by name",
        output = "responses::StructListResult",
        title = "Struct lookup by name",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn search_structs(
        &self,
        Parameters(req): Parameters<StructsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let query = try_param!(req.resolve_query());
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let coverage = self.analysis_coverage().await;
        match self.worker.structs(query, timeout_secs).await {
            Ok(result) => Ok(structured_with_coverage(
                &result,
                &coverage,
                "search_structs",
            )),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Apply a type to an address, or to a stack variable with stack_offset/stack_name. \
        A type IDA did not apply answers isError=true; the error detail keeps applied/code.",
        output = "responses::ApplyTypesOutput",
        title = "Give a location a type",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn apply_types(
        &self,
        Parameters(req): Parameters<ApplyTypesRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let relaxed = req.relaxed.unwrap_or(false);
        let delay = req.delay.unwrap_or(false);
        let strict = req.strict.unwrap_or(false);
        match self
            .worker
            .apply_types(crate::ida::ApplyTypesSpec {
                addr,
                name: req.target_name.clone(),
                offset,
                stack_offset: req.stack_offset,
                stack_name: req.stack_name.clone(),
                decl: req.decl.clone(),
                type_name: req.type_name.clone(),
                relaxed,
                delay,
                strict,
            })
            .await
        {
            Ok(result) => match type_mutation_failure(&result) {
                // Both arms of apply_types report failure in the payload: the
                // address arm with `applied: false`, the stack arm with a
                // non-zero `code`.
                Some(reason) => Ok(structured_failure(
                    &result,
                    "apply_types",
                    format!("apply_types did not apply the type: {reason}. Nothing was changed."),
                )),
                None => Ok(structured_value(&result, "apply_types")),
            },
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Infer/guess type at an address",
        output = "responses::GuessTypeResult",
        title = "Guess the type at a location",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    async fn infer_types(
        &self,
        Parameters(req): Parameters<InferTypesRequest>,
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
            .infer_types(addr, req.target_name.clone(), offset)
            .await
        {
            Ok(result) => Ok(structured_value(&result, "infer_types")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}
