#[vibrev_tool_router(
    router = editing_router,
    vis = "pub(crate)",
    defs = "editing_defs",
    cli = "editing_cli",
    call = "editing_call",
)]
impl IdaMcpServer {
    #[vibrev_tool(
        description = "Look up Lumina metadata for a function without applying it",
        output = "responses::LuminaPullOutput",
        title = "Preview Lumina metadata",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = true
        )
    )]
    #[instrument(skip_all, fields(target_name = ?req.target_name))]
    async fn lumina_lookup(
        &self,
        Parameters(req): Parameters<LuminaLookupRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let addr = try_param!(req.address.as_ref().map(AddressArg::to_single).transpose());
        match self
            .worker
            .lumina_lookup(addr, req.target_name.clone(), offset, timeout_secs)
            .await
        {
            Ok(result) => Ok(structured_json(result)),
            Err(err) => Ok(err.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Pull and apply Lumina metadata to a function",
        output = "responses::LuminaPullOutput",
        title = "Pull Lumina metadata in",
        annotations(read_only = false, destructive = true, open_world = true)
    )]
    #[instrument(skip_all, fields(target_name = ?req.target_name, force = req.force))]
    async fn lumina_apply(
        &self,
        Parameters(req): Parameters<LuminaApplyRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let force = req.force.unwrap_or(false);
        // Validated and then dropped: IDA cannot be told to abandon a Lumina
        // apply once it has started, so a timeout here could only report a lie
        // about what the database now contains. Rejecting a malformed value is
        // still this tool's job.
        let _timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        let addr = try_param!(req.address.as_ref().map(AddressArg::to_single).transpose());
        match self
            .worker
            .lumina_apply(addr, req.target_name.clone(), offset, force)
            .await
        {
            Ok(result) => Ok(structured_json(result)),
            Err(err) => Ok(err.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Add or replace a bookmark at an address",
        output = "responses::BookmarkResult",
        title = "Mark an address",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn bookmark_add(
        &self,
        Parameters(req): Parameters<AddBookmarkRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.to_single() {
            Ok(addr) => addr,
            Err(error) => return Ok(error.to_tool_result()),
        };
        match self
            .worker
            .add_bookmark(addr, req.description.clone())
            .await
        {
            Ok(result) => Ok(structured_value(&result, "bookmark_add")),
            Err(error) => Ok(error.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Execute a low-level IDA SDK database mutation",
        output = "responses::SdkMutationOutput",
        title = "Low-level database edit",
        annotations(read_only = false, destructive = true, open_world = false),
        cli(positional = "action")
    )]
    async fn sdk_mutation(
        &self,
        Parameters(req): Parameters<SdkMutationRequest>,
    ) -> Result<CallToolResult, McpError> {
        let required_address = |value: Option<&AddressArg>, field: &str| {
            value
                .ok_or_else(|| ToolError::InvalidParams(format!("{field} is required")))
                .and_then(AddressArg::to_single)
        };
        let address_list = |values: Option<Vec<AddressArg>>, field: &str| {
            let values = values.unwrap_or_default();
            if values.len() > 10_000 {
                return Err(ToolError::InvalidParams(format!(
                    "{field} exceeds the 10000-item limit"
                )));
            }
            values
                .iter()
                .map(AddressArg::to_single)
                .collect::<Result<Vec<_>, _>>()
        };
        let mutation = match req.action.as_str() {
            "save" => SdkMutation::Save { path: req.path },
            "define_func" => {
                let start = try_param!(required_address(req.start.as_ref(), "start"));
                let end = try_param!(req.end.as_ref().map(AddressArg::to_single).transpose());
                SdkMutation::DefineFunc { start, end }
            }
            "define_code" => SdkMutation::DefineCode {
                address: try_param!(required_address(req.address.as_ref(), "address")),
            },
            "undefine" => SdkMutation::Undefine {
                address: try_param!(required_address(req.address.as_ref(), "address")),
                size: match req.size.filter(|size| *size > 0).map(|size| size as u64) {
                    Some(size) => size,
                    None => {
                        return Ok(ToolError::InvalidParams(
                            "positive size is required".to_string(),
                        )
                        .to_tool_result())
                    }
                },
            },
            "reanalyze" => SdkMutation::Reanalyze {
                start: try_param!(required_address(req.start.as_ref(), "start")),
                end: try_param!(required_address(req.end.as_ref(), "end")),
            },
            "mark_cfunc_dirty" => SdkMutation::MarkCfuncDirty {
                address: try_param!(required_address(req.address.as_ref(), "address")),
            },
            "enum_upsert_member" => SdkMutation::EnumUpsertMember {
                enum_name: req.enum_name.unwrap_or_default(),
                member_name: req.member_name.unwrap_or_default(),
                value: try_param!(req
                    .value
                    .as_ref()
                    .ok_or_else(|| ToolError::InvalidParams("value is required".to_string()))
                    .and_then(crate::server::address::AddressArg::to_single)),
                bitfield: req.bitfield.unwrap_or(false),
            },
            "rename_variable" => SdkMutation::RenameVariable {
                function_address: try_param!(required_address(
                    req.function_address.as_ref(),
                    "function_address"
                )),
                old_name: req.old_name.unwrap_or_default(),
                new_name: req.new_name.unwrap_or_default(),
                stack: req.stack.unwrap_or(false),
            },
            "survey_metrics" => SdkMutation::SurveyMetrics {
                function_addresses: try_param!(address_list(
                    req.function_addresses,
                    "function_addresses"
                )),
                string_addresses: try_param!(address_list(
                    req.string_addresses,
                    "string_addresses"
                )),
            },
            "signature_bytes" => SdkMutation::SignatureBytes {
                address: try_param!(required_address(req.address.as_ref(), "address")),
                size: match req.size.and_then(|size| usize::try_from(size).ok()) {
                    Some(size) => size,
                    None => {
                        return Ok(ToolError::InvalidParams(
                            "signature size is required".to_string(),
                        )
                        .to_tool_result())
                    }
                },
                wildcard_operands: req.wildcard_operands.unwrap_or(true),
            },
            "set_operand_type" => SdkMutation::SetOperandType {
                address: try_param!(required_address(req.address.as_ref(), "address")),
                operand: req.operand.unwrap_or(0),
                kind: req.kind.unwrap_or_default(),
                target: try_param!(req.target.as_ref().map(AddressArg::to_single).transpose()),
                struct_name: req.struct_name,
                delta: req.delta.unwrap_or(0),
            },
            "make_data" => SdkMutation::MakeData {
                address: try_param!(required_address(req.address.as_ref(), "address")),
                declaration: req.declaration.unwrap_or_default(),
                name: req.name,
                delete_existing: req.delete_existing.unwrap_or(true),
            },
            action => {
                return Ok(ToolError::InvalidParams(format!(
                    "unknown SDK mutation action: {action}"
                ))
                .to_tool_result())
            }
        };
        match self.worker.sdk_mutation(mutation).await {
            Ok(result) => Ok(structured_json(result)),
            Err(error) => Ok(error.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Append a line or function comment",
        output = "responses::AppendCommentResult",
        title = "Add to an existing comment",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn comment_append(
        &self,
        Parameters(req): Parameters<AppendCommentRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.to_single() {
            Ok(addr) => addr,
            Err(error) => return Ok(error.to_tool_result()),
        };
        match self
            .worker
            .append_comment(
                addr,
                req.comment.clone(),
                req.scope
                    .unwrap_or(requests::CommentScope::Auto)
                    .as_str()
                    .to_string(),
                req.dedupe.unwrap_or(true),
            )
            .await
        {
            Ok(result) => Ok(structured_value(&result, "comment_append")),
            Err(error) => Ok(error.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Set comments at an address",
        output = "responses::SetCommentsResult",
        title = "Replace comments at an address",
        annotations(read_only = false, destructive = false, open_world = false),
        cli(positional = "comment")
    )]
    async fn set_comments(
        &self,
        Parameters(req): Parameters<SetCommentsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let repeatable = req.repeatable.unwrap_or(false);
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .set_comments(
                addr,
                req.target_name.clone(),
                offset,
                req.comment.clone(),
                repeatable,
            )
            .await
        {
            Ok(result) => Ok(structured_value(&result, "set_comments")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Patch instructions with assembly text",
        output = "responses::PatchAsmResult",
        title = "Assemble over an instruction",
        annotations(read_only = false, destructive = true),
        cli(positional = "line")
    )]
    async fn patch_asm(
        &self,
        Parameters(req): Parameters<PatchAsmRequest>,
    ) -> Result<CallToolResult, McpError> {
        let offset = req.offset.unwrap_or(0);
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        match self
            .worker
            .patch_asm(addr, req.target_name.clone(), offset, req.line.clone())
            .await
        {
            Ok(result) => Ok(structured_value(&result, "patch_asm")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    // The one non-read-only tool in the slice. `idempotent` is deliberately not
    // stated: `tool_annotations_for` does not set it for this arm, and the
    // macro only *requires* `read_only`, so the published annotations are
    // byte-identical to the table's.
    #[vibrev_tool(
        description = "Rename symbols",
        output = "responses::RenameResult",
        title = "Give a symbol a new name",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    async fn rename(
        &self,
        Parameters(req): Parameters<RenameRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let flags = try_param!(parse_optional_unsigned::<i32>(req.flags, "flags")).unwrap_or(0);
        match self
            .worker
            .rename(addr, req.current_name.clone(), req.name.clone(), flags)
            .await
        {
            Ok(result) => Ok(structured_value(&result, "rename")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Patch bytes at an address",
        output = "responses::PatchResult",
        title = "Overwrite bytes",
        annotations(read_only = false, destructive = true),
        cli(positional = "bytes")
    )]
    async fn patch(
        &self,
        Parameters(req): Parameters<PatchRequest>,
    ) -> Result<CallToolResult, McpError> {
        let addr = match req.address.as_ref() {
            Some(val) => match val.to_single() {
                Ok(v) => Some(v),
                Err(e) => return Ok(e.to_tool_result()),
            },
            None => None,
        };
        let offset = req.offset.unwrap_or(0);
        let bytes = match value_to_bytes(&req.bytes) {
            Ok(v) => v,
            Err(e) => return Ok(e.to_tool_result()),
        };
        match self
            .worker
            .patch_bytes(addr, req.target_name.clone(), offset, bytes)
            .await
        {
            Ok(result) => Ok(structured_value(&result, "patch")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }
}
