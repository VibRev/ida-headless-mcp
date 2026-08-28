#[vibrev_tool_router(
    router = database_router,
    vis = "pub(crate)",
    defs = "database_defs",
    cli = "database_cli",
    call = "database_call",
)]
impl IdaMcpServer {
    #[tool(
        description = "Open an IDA database (.i64/.idb) or raw binary (Mach-O/ELF/PE). \
        Raw binaries are saved as .i64 alongside the input and later raw-path opens reuse \
        that database unless rebuild=true is set. \
        For raw binaries, auto-analysis is OFF by default — check analysis_status; \
        call analyze_funcs(background=true) for full xrefs/decompile. \
        Returns close_token in HTTP/SSE mode (provide to close_idb). \
        Inputs >50 MiB with auto_analyse=true may route to a background task; \
        poll task_status(analysis_task_id) when present. \
        Call tool_help('open_idb') for full details.",
        output_schema = responses::schema::<responses::OpenIdbOutput>(),
        title = "Open a binary or database",
        annotations(read_only_hint = false, destructive_hint = false, open_world_hint = false)
    )]
    #[instrument(skip_all, fields(path = %req.path, mrtr_retry = request_state.is_some()))]
    async fn open_idb(
        &self,
        ctx: RequestContext<RoleServer>,
        RequestState(request_state): RequestState,
        ToolInputResponses(input_responses): ToolInputResponses,
        Parameters(req): Parameters<OpenIdbRequest>,
    ) -> Result<CallToolResponse, McpError> {
        debug!("Tool call: open_idb");
        let path = req.path.trim().to_string();
        // Validate path (prevent directory traversal, check extension)
        if !Self::validate_path(&path) {
            return Ok(ToolError::InvalidPath(path).to_tool_result().into());
        }
        let timeout_secs = match parse_optional_unsigned::<u64>(req.timeout_secs, "timeout_secs") {
            Ok(timeout_secs) => timeout_secs,
            Err(error) => return Ok(error.to_tool_result().into()),
        };

        let debug_info_path = req.normalized_debug_info_path();
        let file_type = req.normalized_file_type();
        let worker_extra_args = if matches!(self.mode, ServerMode::Worker) {
            req.worker_extra_args.clone()
        } else {
            Vec::new()
        };
        let worker_idb_out = if matches!(self.mode, ServerMode::Worker) {
            req.worker_idb_out.clone()
        } else {
            None
        };
        let open_timeout_secs = timeout_secs.unwrap_or(300).min(MAX_TIMEOUT_SECS);
        let user_auto_analyse = req.auto_analyse.unwrap_or(false);
        let large_input_size = if !matches!(self.mode, ServerMode::Worker)
            && user_auto_analyse
            && !Self::is_database_path(&path)
        {
            Self::input_size_above_threshold(&path)
        } else {
            None
        };
        let route_to_background = match large_input_size {
            Some(size) => match self
                .choose_open_idb_background(
                    &ctx,
                    &path,
                    size,
                    timeout_secs,
                    request_state,
                    input_responses,
                )
                .await?
            {
                OpenIdbBackgroundDecision::Ready(background) => background,
                OpenIdbBackgroundDecision::InputRequired(result) => return Ok(result.into()),
            },
            None if request_state.is_some() || input_responses.is_some() => {
                return Err(McpError::invalid_params(
                    "requestState/inputResponses do not match an active open_idb elicitation",
                    None,
                ));
            }
            None => false,
        };
        // Open the database with auto_analyse disabled when we plan to spawn
        // analysis as a background task; the open call itself stays fast and
        // analysis runs without the foreground timeout cap.
        let effective_auto_analyse = user_auto_analyse && !route_to_background;

        let leftover_input = crate::expand_path(&path);
        let leftover_preserve = leftover::existing_leftover_parts(&leftover_input);
        let leftover_idb_out = worker_idb_out
            .as_deref()
            .map(str::trim)
            .filter(|out| !out.is_empty())
            .map(|out| {
                let path = crate::expand_path(out);
                let preserve = leftover::existing_leftover_parts(&path);
                (path, preserve)
            });

        let open_result = self
            .run_foreground_operation(
                &ctx,
                "open_idb",
                path.clone(),
                timeout_secs,
                300,
                |progress_tx, cancel| {
                    self.worker.open_observed(
                        crate::ida::OpenSpec {
                            path: path.clone(),
                            load_debug_info: req.load_debug_info.unwrap_or(false),
                            debug_info_path: debug_info_path.clone(),
                            debug_info_verbose: req.debug_info_verbose.unwrap_or(false),
                            force: req.force.unwrap_or(false),
                            rebuild: req.rebuild.unwrap_or(false),
                            file_type: file_type.clone(),
                            auto_analyse: effective_auto_analyse,
                            extra_args: worker_extra_args.clone(),
                            idb_out: worker_idb_out.clone(),
                        },
                        Some(open_timeout_secs),
                        Some(progress_tx),
                        Some(cancel),
                    )
                },
            )
            .await;
        if open_result.is_err() {
            leftover::cleanup_leftover_parts(&leftover_input, &leftover_preserve);
            if let Some((path, preserve)) = &leftover_idb_out {
                leftover::cleanup_leftover_parts(path, preserve);
            }
        }
        match open_result {
            Ok(info) => {
                let close_token = self.http_close_grant();
                let analysis_task = if route_to_background && !info.analysis_status.auto_is_ok {
                    let cancel_token = self.background_lifetime(&ctx.meta).child_token();
                    let owner = self.task_owner(&ctx.meta);
                    Some(match self.spawn_analyze_funcs_task(&owner, cancel_token) {
                        Ok(task_id) => Ok((task_id, "started")),
                        Err(task::TaskCreateError::AlreadyRunning(existing_id)) => {
                            Ok((existing_id, "already_running"))
                        }
                        Err(error) => Err(task_create_error_to_tool_error(error).to_string()),
                    })
                } else {
                    None
                };
                let mut value = match serde_json::to_value(&info) {
                    Ok(value) => value,
                    // Unreachable for `DbInfo`, which is plain data. Emitting
                    // text with no `structuredContent` would break the schema
                    // this tool advertises, so fail loudly instead.
                    Err(error) => {
                        warn!(error = %error, "open_idb response could not be serialized");
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "open_idb produced a response that could not be serialized: {error}"
                        ))])
                        .into());
                    }
                };
                if let Value::Object(map) = &mut value {
                    let mut quick_tools = vec![
                        "list_functions",
                        "resolve_function",
                        "disasm_by_name",
                        "strings",
                        "analysis_status",
                        "analyze_funcs",
                        "close_idb",
                    ];
                    if info.analysis_status.auto_is_ok {
                        quick_tools.extend(["decompile", "xrefs_to"]);
                    }
                    map.insert("quick_tools".to_string(), json!(quick_tools));
                    if !matches!(self.mode, ServerMode::Worker) {
                        map.insert("session_id".to_string(), json!(self.session_id));
                        self.apply_close_metadata(map, close_token);
                    }
                    if let Some(analysis_task) = analysis_task {
                        match analysis_task {
                            Ok((task_id, status)) => {
                                let reason = format!(
                                    "Input size exceeded {} MiB; auto-analysis routed to a background task. Poll task_status(task_id) for progress.",
                                    OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES / (1024 * 1024)
                                );
                                map.insert("analysis_background".to_string(), json!(true));
                                map.insert("analysis_started".to_string(), json!(true));
                                map.insert("analysis_task_id".to_string(), json!(task_id));
                                map.insert("analysis_task_status".to_string(), json!(status));
                                map.insert("analysis_background_reason".to_string(), json!(reason));
                            }
                            Err(error) => {
                                map.insert("analysis_background".to_string(), json!(false));
                                map.insert("analysis_started".to_string(), json!(false));
                                map.insert(
                                    "analysis_task_status".to_string(),
                                    json!("not_started"),
                                );
                                map.insert("analysis_background_error".to_string(), json!(error));
                            }
                        }
                    }
                }
                Ok(structured_json(value).into())
            }
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                "open_idb",
                timeout_secs,
                &snapshot,
                None,
            ))
            .to_tool_result()
            .into()),
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("open_idb", &snapshot),
            )
            .to_tool_result()
            .into()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result().into()),
        }
    }

    /// Returns the input size in bytes when it strictly exceeds the
    /// auto-background threshold; `None` otherwise (including when the path
    /// can't be stat'd, e.g. for raw arguments that aren't real files).
    fn input_size_above_threshold(path: &str) -> Option<u64> {
        let meta = std::fs::metadata(crate::expand_path(path.trim())).ok()?;
        if !meta.is_file() {
            return None;
        }
        let size = meta.len();
        (size > OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES).then_some(size)
    }

    fn is_database_path(path: &str) -> bool {
        crate::expand_path(path.trim())
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| {
                let ext = ext.to_ascii_lowercase();
                ext == "i64" || ext == "idb" || ext == "id0"
            })
            .unwrap_or(false)
    }

    fn open_idb_elicitation_timeout_secs(request_timeout_secs: Option<u64>) -> u64 {
        request_timeout_secs
            .unwrap_or(OPEN_IDB_ELICITATION_TIMEOUT_SECS)
            .min(MAX_TIMEOUT_SECS)
            .min(OPEN_IDB_ELICITATION_TIMEOUT_SECS)
    }

    fn open_idb_background_prompt(path: &str, size_bytes: u64) -> String {
        let size_mib = size_bytes / (1024 * 1024);
        let threshold_mib = OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES / (1024 * 1024);
        format!(
            "'{path}' is {size_mib} MiB (threshold {threshold_mib} MiB). \
             Run auto-analysis as a background task with no timeout? \
             Choosing 'no' runs it inline (capped at the foreground timeout)."
        )
    }

    /// Decide whether `open_idb` should route auto-analysis to a background
    /// task. Asks the user via MCP elicitation when the client advertises the
    /// capability; falls back to "background" silently otherwise so large
    /// binaries don't get killed by the foreground timeout. Unanswered prompts
    /// time out to "background"; explicit decline/cancel from a capable client
    /// preserves the legacy foreground behavior.
    async fn choose_open_idb_background(
        &self,
        ctx: &RequestContext<RoleServer>,
        path: &str,
        size_bytes: u64,
        request_timeout_secs: Option<u64>,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        use rmcp::service::{ElicitationError, ServiceError};

        let size_mib = size_bytes / (1024 * 1024);
        let modern_protocol = ctx
            .protocol_version()
            .is_some_and(|version| version >= ProtocolVersion::V_2026_07_28);
        if modern_protocol {
            return self.modern_choose_open_idb_background(
                ctx,
                path,
                size_bytes,
                request_state,
                input_responses,
            );
        }

        if request_state.is_some() || input_responses.is_some() {
            return Err(McpError::invalid_params(
                "requestState and inputResponses require MCP 2026-07-28",
                None,
            ));
        }

        if ctx.peer.supported_elicitation_modes().is_empty() {
            info!(
                path,
                size_mib, "client lacks elicitation; routing open_idb auto-analysis to background"
            );
            return Ok(OpenIdbBackgroundDecision::Ready(true));
        }

        let prompt = Self::open_idb_background_prompt(path, size_bytes);

        let elicitation_timeout_secs =
            Self::open_idb_elicitation_timeout_secs(request_timeout_secs);
        let client_cancel = ctx.ct.clone();
        let elicitation = ctx.peer.elicit_with_timeout::<OpenIdbBackgroundChoice>(
            prompt,
            Some(Duration::from_secs(elicitation_timeout_secs)),
        );

        let result = tokio::select! {
            biased;
            _ = client_cancel.cancelled() => {
                info!(
                    path,
                    size_mib,
                    "open_idb elicitation cancelled with client request"
                );
                return Ok(OpenIdbBackgroundDecision::Ready(false));
            }
            result = elicitation => result,
        };

        let background = match result {
            Ok(Some(choice)) => choice.background.unwrap_or(true),
            // Some clients return Accept with no content for action-only
            // confirmations; treat that as a "yes, background".
            // `Ok(None)` is not expected from the current typed API, but keep
            // the arm defensive in case that contract broadens later.
            Ok(None) | Err(ElicitationError::NoContent) => true,
            Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => false,
            Err(ElicitationError::CapabilityNotSupported) => true,
            Err(ElicitationError::Service(ServiceError::Timeout { .. })) => {
                info!(
                    path,
                    size_mib,
                    elicitation_timeout_secs,
                    "open_idb elicitation timed out; routing auto-analysis to background"
                );
                true
            }
            Err(err) => {
                warn!(
                    path,
                    size_mib, elicitation_timeout_secs, %err,
                    "open_idb elicitation failed; routing to background to avoid timeout regression"
                );
                true
            }
        };
        Ok(OpenIdbBackgroundDecision::Ready(background))
    }

    /// MCP 2026 (MRTR) preamble for the background decision: validates the
    /// requestState/capability pairing before the sealed-state round-trip.
    fn modern_choose_open_idb_background(
        &self,
        ctx: &RequestContext<RoleServer>,
        path: &str,
        size_bytes: u64,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        if request_state.is_none() && input_responses.is_some() {
            return Err(McpError::invalid_params(
                "inputResponses require a matching requestState",
                None,
            ));
        }
        let supports_form_elicitation = ctx
            .client_capabilities()
            .and_then(|capabilities| capabilities.elicitation)
            .and_then(|elicitation| elicitation.form)
            .is_some();
        if request_state.is_none() && !supports_form_elicitation {
            info!(
                path,
                size_mib = size_bytes / (1024 * 1024),
                "client lacks form elicitation; routing open_idb auto-analysis to background"
            );
            return Ok(OpenIdbBackgroundDecision::Ready(true));
        }
        if !supports_form_elicitation {
            return Err(McpError::invalid_params(
                "MRTR retry omitted the form elicitation capability",
                None,
            ));
        }
        self.modern_open_idb_background_decision(path, size_bytes, request_state, input_responses)
    }

    fn modern_open_idb_background_decision(
        &self,
        path: &str,
        size_bytes: u64,
        request_state: Option<String>,
        input_responses: Option<InputResponses>,
    ) -> Result<OpenIdbBackgroundDecision, McpError> {
        const STAGE: &[u8] = b"open_idb/background-confirmation/v1";
        const INPUT_KEY: &str = "background";

        let associated_data = format!("tools/call:open_idb\0{path}\0{size_bytes}");
        let Some(sealed) = request_state else {
            if input_responses.is_some() {
                return Err(McpError::invalid_params(
                    "inputResponses require a matching requestState",
                    None,
                ));
            }
            let sealed = self.request_state_codec.seal_with(
                STAGE,
                &SealOptions::new()
                    .associated_data(associated_data.as_bytes())
                    .ttl(Duration::from_secs(OPEN_IDB_REQUEST_STATE_TTL_SECS)),
            );
            // Reuse the same schema the legacy elicitation path derives from
            // `OpenIdbBackgroundChoice`, so the two protocols cannot drift.
            let requested_schema = ElicitationSchema::from_type::<OpenIdbBackgroundChoice>()
                .map_err(|error| {
                    McpError::internal_error(
                        format!("failed to build open_idb elicitation schema: {error}"),
                        None,
                    )
                })?;
            let mut input_requests = InputRequests::new();
            input_requests.insert(
                INPUT_KEY.to_string(),
                InputRequest::Elicitation(ElicitRequest::new(
                    ElicitRequestParams::FormElicitationParams {
                        meta: None,
                        message: Self::open_idb_background_prompt(path, size_bytes),
                        requested_schema,
                    },
                )),
            );
            return Ok(OpenIdbBackgroundDecision::InputRequired(
                InputRequiredResult::new(Some(input_requests), Some(sealed)),
            ));
        };

        let opened = self
            .request_state_codec
            .open_with(&sealed, associated_data.as_bytes())
            .map_err(|_| {
                McpError::invalid_params("expired, tampered, or unknown requestState", None)
            })?;
        if opened != STAGE {
            return Err(McpError::invalid_params(
                "requestState belongs to a different MRTR stage",
                None,
            ));
        }
        let response = input_responses
            .as_ref()
            .and_then(|responses| responses.get(INPUT_KEY))
            .ok_or_else(|| {
                McpError::invalid_params("missing background elicitation response", None)
            })?;
        let response: ElicitResult = serde_json::from_value(response.clone()).map_err(|_| {
            McpError::invalid_params("invalid background elicitation response action", None)
        })?;
        let background = match response.action {
            ElicitationAction::Accept => response
                .content
                .and_then(|content| serde_json::from_value::<OpenIdbBackgroundChoice>(content).ok())
                .and_then(|choice| choice.background)
                .unwrap_or(true),
            ElicitationAction::Decline | ElicitationAction::Cancel => false,
            // `ElicitationAction` is #[non_exhaustive]; treat unknown future
            // actions as a decline so we never background without consent.
            _ => false,
        };
        Ok(OpenIdbBackgroundDecision::Ready(background))
    }

    #[vibrev_tool(
        description = "Load external debug info (e.g., DWARF/dSYM) into the current database. \
        If path is omitted, attempts to locate a sibling .dSYM for the currently-open database.",
        output = "responses::LoadDebugInfoOutput",
        title = "Attach external symbols",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    #[instrument(skip_all, fields(has_path = req.path.is_some()))]
    async fn load_debug_info(
        &self,
        Parameters(req): Parameters<LoadDebugInfoRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: load_debug_info");
        match self
            .worker
            .load_debug_info(req.path, req.verbose.unwrap_or(false))
            .await
        {
            Ok(info) => Ok(structured_value(&info, "load_debug_info")),
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Report auto-analysis status (auto_is_ok, auto_state). \
        Use this to check whether analysis-dependent tools (xrefs, decompile) are fully ready.",
        output = "responses::AnalysisStatusOutput",
        title = "Auto-analysis readiness",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all)]
    async fn analysis_status(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analysis_status");
        match self.worker.analysis_status().await {
            Ok(status) => {
                let mut value =
                    serde_json::to_value(&status).unwrap_or_else(|_| json!(format!("{status:?}")));
                if !matches!(self.mode, ServerMode::Worker)
                    && let Value::Object(map) = &mut value
                {
                    map.insert("session_id".to_string(), json!(self.session_id));
                }
                Ok(structured_json(value))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Close the currently open IDA database. \
        Call this when you're done analyzing to free resources. \
        In legacy HTTP/SSE, the owning session can close directly. Otherwise, \
        including MCP 2026, provide the close_token returned by open_idb, or \
        set force=true from a trusted client if that token was lost. \
        Stdio clients can close directly without a token.",
        output = "responses::CloseIdbOutput",
        title = "Release the open database",
        annotations(read_only = false, destructive = true, open_world = false),
        cli(none)
    )]
    #[instrument(skip_all, fields(has_token = req.token.is_some(), force = ?req.force))]
    async fn close_idb(
        &self,
        Parameters(req): Parameters<CloseIdbRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!("Tool call: close_idb received");
        if matches!(self.mode, ServerMode::Http) {
            match self.worker.authorize_close(
                &self.session_id,
                req.token.as_deref(),
                req.force.unwrap_or(false),
            ) {
                CloseAuthorization::Granted => {}
                CloseAuthorization::GrantedByOverride {
                    previous_owner_session_id,
                } => {
                    info!(
                        previous_owner_session_id = ?previous_owner_session_id,
                        "close_idb overriding previous HTTP owner session"
                    );
                }
                CloseAuthorization::Denied { owner_session_id } => {
                    info!(owner_session_id = ?owner_session_id, "close_idb ignored: owner token required");
                    return Ok(structured_json(json!({
                        "closed": false,
                        "reason": "owner token required",
                        "owner_session_id": owner_session_id,
                        "hint": "Provide the close_token from open_idb, or call close_idb(force=true) from a trusted client if that token was lost."
                    })));
                }
            }
        }
        match self.worker.close_with_save(req.save.unwrap_or(true)).await {
            Ok(()) => {
                self.worker.clear_close_token();
                info!("Tool call: close_idb completed successfully");
                // The text block keeps the human sentence clients already show;
                // `structuredContent` carries the machine-readable outcome.
                Ok(structured_result(
                    "Database closed".to_string(),
                    json!({ "closed": true }),
                ))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Discover available tools by query or category. \
        Use this to find the right tool for your task before calling tool_help for full details.",
        output = "responses::ToolCatalogOutput",
        title = "Browse the toolbox",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(no_session)
    )]
    #[instrument(skip_all)]
    async fn tool_catalog(
        &self,
        Parameters(req): Parameters<ToolCatalogRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_catalog");
        let limit = try_param!(parse_optional_unsigned::<usize>(req.limit, "limit"))
            .unwrap_or(7)
            .min(15);
        let filter = self.filter.clone();
        let filtering_active = filter.is_active();

        // If category specified, list tools in that category
        if let Some(cat) = req.category.map(catalog_category) {
            // Counted before `limit` applies: the whole point of `total` is to
            // be the number the page is not.
            let matched: Vec<_> = catalog::tools_in_category(cat)
                .filter(|name| filter.allows(name))
                .collect();
            let total = matched.len();
            let tools: Vec<_> = matched
                .into_iter()
                .take(limit)
                .map(|name| {
                    json!({
                        "name": name,
                        "description": catalog::short_description_of(name),
                        "category": cat.as_str(),
                    })
                })
                .collect();

            let mut payload = json!({
                "category": cat.as_str(),
                "category_description": cat.description(),
                "tools": tools,
                "total": total,
                "hint": "Use tool_help(name) for full documentation and examples"
            });
            if filtering_active {
                payload["filtering_active"] = json!(true);
            }
            return Ok(structured_json(payload));
        }

        // If query specified, search for matching tools
        if let Some(query) = &req.query {
            let matched: Vec<_> = catalog::search(query, usize::MAX)
                .into_iter()
                .filter(|name| filter.allows(name))
                .collect();
            let total = matched.len();
            let tools: Vec<_> = matched
                .into_iter()
                .take(limit)
                .map(|name| {
                    json!({
                        "name": name,
                        "description": catalog::short_description_of(name),
                        "category": catalog::category_of(name).map(ToolCategory::as_str),
                    })
                })
                .collect();

            let mut payload = json!({
                "query": query,
                "tools": tools,
                "total": total,
                "hint": "Use tool_help(name) for full documentation and examples"
            });
            if filtering_active {
                payload["filtering_active"] = json!(true);
            }
            return Ok(structured_json(payload));
        }

        // No query or category - list all categories. Counts reflect enabled
        // tools so users see exactly what's available under the active filter.
        let categories: Vec<_> = ToolCategory::all()
            .iter()
            .map(|c| {
                let count = catalog::tools_in_category(*c)
                    .filter(|name| filter.allows(name))
                    .count();
                json!({
                    "category": c.as_str(),
                    "description": c.description(),
                    "tool_count": count,
                })
            })
            .collect();

        let hint = if filtering_active {
            "Use tool_catalog(category='...') to list enabled tools in a category, or tool_catalog(query='...') to search enabled tools. tools/list includes only tools enabled by the current filter."
        } else {
            "Use tool_catalog(category='...') to list tools in a category, or tool_catalog(query='...') to search. tools/list already includes all tools."
        };

        let mut payload = json!({
            "categories": categories,
            "hint": hint
        });
        if filtering_active {
            payload["filtering_active"] = json!(true);
            payload["enabled_tool_count"] =
                json!(filter.advertise(catalog::native_tools()).len());
        }

        Ok(structured_json(payload))
    }

    #[vibrev_tool(
        description = "Get full documentation for a tool including description, parameters schema, and example.",
        output = "responses::ToolHelpOutput",
        title = "Full docs for one tool",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "name", no_session)
    )]
    #[instrument(skip_all)]
    async fn tool_help(
        &self,
        Parameters(req): Parameters<ToolHelpRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: tool_help for {}", req.name);

        // If the tool exists but is filter-disabled, do not leak its schema as
        // available — return a clear disabled message.
        if self.filter.is_active()
            && catalog::native_tool_name(&req.name).is_some()
            && !self.filter.allows(&req.name)
        {
            return Ok(structured_json(json!({
                "error": format!(
                    "tool '{}' is disabled by current filter \
                     (--toolsets/--tools/--exclude-tools/--read-only)",
                    req.name
                ),
                "filtering_active": true,
                "hint": "call tool_catalog to see enabled tools",
            })));
        }

        if let Some(tool) = catalog::native_tool(&req.name) {
            Ok(structured_json(json!({
                "name": tool.name,
                "category": catalog::category_of(&req.name).map(ToolCategory::as_str),
                "description": tool.description,
                "parameters": Value::from(tool.input_schema.as_ref().clone()),
                "annotations": tool.annotations,
            })))
        } else {
            // Suggest similar tools
            let suggestion_names = catalog::search(&req.name, 3);

            Ok(structured_json(json!({
                "error": format!("Tool '{}' not found", req.name),
                "suggestions": suggestion_names,
                "hint": "Use tool_catalog to discover available tools"
            })))
        }
    }

    #[vibrev_tool(
        description = "Get IDB metadata (ida-pro-mcp compatibility)",
        output = "responses::IdbMetaOutput",
        title = "Database fingerprint",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all)]
    async fn idb_meta(&self) -> Result<CallToolResult, McpError> {
        debug!("Tool call: idb_meta");
        let coverage = self.analysis_coverage().await;
        match self.worker.idb_meta().await {
            Ok(result) => {
                let mut value =
                    serde_json::to_value(&result).unwrap_or_else(|_| json!(format!("{result:?}")));
                if !matches!(self.mode, ServerMode::Worker)
                    && let Value::Object(map) = &mut value
                {
                    map.insert("session_id".to_string(), json!(self.session_id));
                }
                attach_analysis_coverage(&mut value, &coverage, "idb_meta");
                Ok(structured_json(value))
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Run IDA auto-analysis to completion. \
        Use background=true for large binaries (returns task_id; poll task_status).",
        output_schema = responses::schema::<responses::AnalyzeFuncsOutput>(),
        title = "Run full auto-analysis",
        annotations(read_only_hint = false, destructive_hint = false, open_world_hint = false)
    )]
    async fn analyze_funcs(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<AnalyzeFuncsRequest>,
    ) -> Result<CallToolResult, McpError> {
        if matches!(self.mode, ServerMode::Worker) && req.worker_no_timeout {
            return match self
                .worker
                .analyze_funcs_observed(None, Some(ctx.ct.clone()))
                .await
            {
                Ok(result) => Ok(structured_value(&result, "analyze_funcs")),
                Err(e) => Ok(e.to_tool_result()),
            };
        }
        if req.background.unwrap_or(false) {
            let cancel_token = self.background_lifetime(&ctx.meta).child_token();
            let owner = self.task_owner(&ctx.meta);
            return Ok(self.analyze_funcs_background(&owner, cancel_token));
        }

        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));
        match self
            .run_foreground_operation(
                &ctx,
                "analyze_funcs",
                "current database".to_string(),
                timeout_secs,
                120,
                |progress_tx, cancel| {
                    self.worker
                        .analyze_funcs_observed(Some(progress_tx), Some(cancel))
                },
            )
            .await
        {
            Ok(result) => Ok(structured_value(&result, "analyze_funcs")),
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                "analyze_funcs",
                timeout_secs,
                &snapshot,
                None,
            ))
            .to_tool_result()),
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("analyze_funcs", &snapshot),
            )
            .to_tool_result()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result()),
        }
    }

    /// Spawn auto-analysis as a background task. Returns a task_id immediately;
    /// the IDA worker thread runs auto_wait() while task_status reads the registry
    /// without going through the worker. Only one analysis runs at a time (single
    /// worker thread), so a fixed dedup key blocks another analysis while one
    /// is already in flight. Only the same legacy session receives its existing
    /// task ID; sessionless Runtime requests never do.
    fn analyze_funcs_background(
        &self,
        owner: &task::TaskOwner,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> CallToolResult {
        let payload = match self.spawn_analyze_funcs_task(owner, cancel_token) {
            Ok(task_id) => json!({
                "status": "started",
                "task_id": task_id,
                "message": "Auto-analysis started in background. Poll task_status(task_id) for progress. Other tool calls will block until the IDA worker thread is free.",
            }),
            Err(task::TaskCreateError::AlreadyRunning(existing_id)) => json!({
                "status": "already_running",
                "task_id": existing_id,
                "message": "Auto-analysis is already running. Poll task_status(task_id) for progress.",
            }),
            Err(error) => return task_create_error_to_tool_error(error).to_tool_result(),
        };
        structured_json(payload)
    }

    /// Create the background auto-analysis task and spawn its worker future.
    /// Returns `Ok(task_id)` on success or an error if keyed work is already in
    /// flight. The error carries an existing ID only for the same legacy session.
    fn spawn_analyze_funcs_task(
        &self,
        owner: &task::TaskOwner,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<String, task::TaskCreateError> {
        let task_id = self.task_registry.create_keyed(
            owner,
            "analyze",
            "analyze_funcs",
            "Waiting for IDA auto-analysis to finish",
        )?;

        info!("Spawning background auto-analysis");

        let registry = self.task_registry.clone();
        let worker = self.worker.clone();
        let tid = task_id.clone();
        let worker_cancel_token = cancel_token.clone();

        tokio::spawn(async move {
            // Bridge worker progress updates → task registry messages.
            // The drain task ends when tx is dropped after analyze_funcs_observed returns.
            let (tx, mut rx): (ProgressSender, ProgressReceiver) =
                tokio::sync::mpsc::unbounded_channel();
            let drain_registry = registry.clone();
            let drain_tid = tid.clone();
            tokio::spawn(async move {
                while let Some(update) = rx.recv().await {
                    drain_registry.update_message(&drain_tid, &update.message);
                }
            });

            match worker
                .analyze_funcs_observed(Some(tx), Some(worker_cancel_token.clone()))
                .await
            {
                Ok(value) => match registry.complete_with_cancel_token(
                    &tid,
                    value,
                    &worker_cancel_token,
                    "Cancelled after auto-analysis settled",
                ) {
                    task::TaskSettlement::Completed => {
                        info!("Background auto-analysis completed");
                    }
                    task::TaskSettlement::Cancelled => {
                        info!("Background auto-analysis cancelled after work settled");
                    }
                    task::TaskSettlement::Failed | task::TaskSettlement::Unchanged => {}
                },
                Err(e) => match registry.complete_with_cancel_token(
                    &tid,
                    call_tool_result_to_value(&e.to_tool_result()),
                    &worker_cancel_token,
                    "Cancelled after auto-analysis settled",
                ) {
                    task::TaskSettlement::Completed => {
                        warn!(error = %e, "Background auto-analysis completed with a tool error");
                    }
                    task::TaskSettlement::Cancelled => {
                        info!("Background auto-analysis cancelled after work settled");
                    }
                    task::TaskSettlement::Failed | task::TaskSettlement::Unchanged => {}
                },
            }
        });
        self.task_registry.set_cancel_token(&task_id, cancel_token);
        Ok(task_id)
    }

    #[tool(
        description = "Open a dyld_shared_cache and load a single dylib (e.g. \
        '/usr/lib/libobjc.A.dylib'). Use instead of open_idb for Apple DSCs. \
        If a previously generated .i64 exists for this DSC, opens it immediately, \
        preserving prior analysis. Otherwise on IDA 9.4, opens the DSC header \
        directly in a background task and loads modules through ida_dscu; on \
        older IDA builds, returns task_id and creates the .i64 with idat in the \
        background. Poll task_status(task_id). \
        Use dsc_add_dylib to load more modules, dsc_add_region for raw regions. \
        Call tool_help('open_dsc') for full details.",
        output_schema = responses::schema::<responses::OpenDscOutput>(),
        title = "Open a dyld shared cache",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            open_world_hint = false
        )
    )]
    #[instrument(skip_all, fields(path = %req.path, arch = %req.arch, module = %req.module))]
    async fn open_dsc(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<OpenDscRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: open_dsc");

        if !Self::validate_path(&req.path) {
            return Ok(ToolError::InvalidPath(req.path).to_tool_result());
        }

        let ida_version = try_param!(parse_optional_unsigned::<u8>(
            req.ida_version,
            "ida_version"
        ))
        .unwrap_or(9);
        if ida_version != 8 && ida_version != 9 {
            return Ok(
                ToolError::InvalidParams("ida_version must be 8 or 9".into()).to_tool_result(),
            );
        }

        let file_type = crate::dsc::dsc_file_type(&req.arch, ida_version);
        let frameworks = req.frameworks.unwrap_or_default();
        let dsc_path = std::path::Path::new(&req.path);
        let out_i64 = dsc_path.with_extension("i64");
        // Reuse order: a sibling .i64 (legacy idat output or user-provided)
        // first, then the 9.4 direct-path cache. Pre-9.4 never considers the
        // cache — those databases were written by a newer IDA and cannot be
        // opened there.
        let cache_i64 = direct_dsc_cache_i64_path(dsc_path);
        let existing_i64 = if out_i64.exists() {
            Some(out_i64.clone())
        } else if idalib::SDK_VERSION >= (9, 4) && cache_i64.exists() {
            Some(cache_i64.clone())
        } else {
            None
        };

        match dsc_open_plan(idalib::SDK_VERSION, existing_i64.is_some()) {
            // Existing .i64 databases are already in IDA's database format.
            DscOpenPlan::DirectExistingI64 => {
                // `existing_i64` is Some whenever this plan is selected; the
                // fallback only guards the type system.
                let existing = existing_i64.unwrap_or(out_i64);
                return self
                    .open_dsc_direct(&existing, None, &req.module, &frameworks)
                    .await;
            }
            // IDA 9.4 exposes ida_dscu/dscu_svc_t: the loader can open the DSC
            // header first, then load images on demand in the same idalib process.
            //
            // Do not pass the legacy -T file-type selector here. IDA 9.4's
            // direct idalib open path rejects it with "Unknown switch '-T'".
            DscOpenPlan::BackgroundDirectRawDsc => {
                let idb_out = cache_i64;
                let dsc_ctx = DscBackgroundCtx {
                    open: DscBackgroundOpen::DirectRawDsc {
                        open_path: dsc_path.to_path_buf(),
                        idb_out: idb_out.clone(),
                    },
                    module: req.module.clone(),
                    frameworks: frameworks.clone(),
                    owner_session_id: matches!(self.mode, ServerMode::Http)
                        .then(|| self.session_id.clone()),
                };
                return self.start_dsc_background(
                    &self.task_owner(&ctx.meta),
                    dsc_path.display().to_string(),
                    &format!(
                        "Opening DSC directly with idalib (idb_out={})...",
                        idb_out.display()
                    ),
                    dsc_ctx,
                    self.background_lifetime(&ctx.meta).child_token(),
                );
            }
            DscOpenPlan::LegacyIdatBackground => {}
        }

        // Legacy path: create the .i64 with idat, which takes minutes.
        // Validate idat exists and write the load script before spawning.
        let idat = match crate::dsc::find_idat() {
            Ok(path) => path,
            Err(e) => return Ok(e.to_tool_result()),
        };

        let script = crate::dsc::dsc_load_script(&req.module, &frameworks);
        let script_dir = dsc_path.parent().unwrap_or(std::path::Path::new("/tmp"));
        let script_path = script_dir.join("ida_mcp_dsc_load.py");
        if let Err(e) = std::fs::write(&script_path, &script) {
            return Ok(
                ToolError::InvalidParams(format!("Failed to write DSC load script: {e}"))
                    .to_tool_result(),
            );
        }

        let log_path = req.log_path.map(std::path::PathBuf::from);
        if let Some(ref lp) = log_path
            && lp.to_string_lossy().contains("..")
        {
            return Ok(ToolError::InvalidParams(
                "log_path must not contain '..' path traversal".into(),
            )
            .to_tool_result());
        }
        let idat_args = crate::dsc::idat_dsc_args(
            dsc_path,
            &out_i64,
            &script_path,
            &file_type,
            log_path.as_deref(),
        );
        let dedup_key = out_i64.display().to_string();

        let dsc_ctx = DscBackgroundCtx {
            open: DscBackgroundOpen::LegacyIdat {
                idat,
                idat_args,
                script_path,
                log_path,
                out_i64,
            },
            module: req.module.clone(),
            frameworks,
            owner_session_id: matches!(self.mode, ServerMode::Http)
                .then(|| self.session_id.clone()),
        };
        self.start_dsc_background(
            &self.task_owner(&ctx.meta),
            dedup_key,
            "Running idat to create .i64 from DSC...",
            dsc_ctx,
            self.background_lifetime(&ctx.meta).child_token(),
        )
    }

    #[vibrev_tool(
        description = "Load an additional dylib into an open DSC database \
        (requires prior open_dsc). Skips full auto-analysis for speed; \
        check analysis_status and run analyze_funcs if needed.",
        output = "responses::DscAddDylibOutput",
        title = "Map a dylib out of the shared cache",
        annotations(read_only = false, destructive = false, open_world = false),
        cli(positional = "module")
    )]
    #[instrument(skip_all, fields(module = %req.module))]
    async fn dsc_add_dylib(
        &self,
        Parameters(req): Parameters<DscAddDylibRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_dylib");

        let module = req.module.trim().to_string();
        if module.is_empty() {
            return Ok(ToolError::InvalidParams("module must not be empty".into()).to_tool_result());
        }
        if !module.starts_with('/') {
            return Ok(ToolError::InvalidParams(
                "module must be an absolute path (start with '/')".into(),
            )
            .to_tool_result());
        }
        if module.contains("..") {
            return Ok(ToolError::InvalidParams(
                "module must not contain '..' path traversal".into(),
            )
            .to_tool_result());
        }

        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(300)
        .min(MAX_TIMEOUT_SECS);
        match self
            .worker
            .dsc_load_image(&module, Some(timeout_secs))
            .await
        {
            Ok(image) => {
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(module = %module, error = %err, "failed to fetch analysis_status after dsc_add_dylib");
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for the newly loaded module.",
                );
                Ok(structured_json(json!({
                    "success": true,
                    "module": module,
                    "message": format!(
                        "Successfully loaded {module} into the database. \
                         Full auto-analysis was not forced."
                    ),
                    "dsc_backend": "dscu",
                    "image": image,
                    "analysis_status": analysis_status,
                    "analysis_ready": analysis_ready,
                    "next_steps": next_steps,
                })))
            }
            Err(ToolError::Timeout(secs)) => {
                let message =
                    format!("dsc_add_dylib timed out after {secs} seconds while loading {module}");
                warn!(module = %module, timeout_secs = secs, "dsc_add_dylib timed out");
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(ToolError::TimeoutDetailed(message)) => {
                warn!(module = %module, timeout_secs, "dsc_add_dylib timed out");
                Ok(ToolError::IdaError(format!(
                    "dsc_add_dylib timed out while loading {module}: {message}"
                ))
                .to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[vibrev_tool(
        description = "Load a DSC region by address into an open DSC database \
        (data/GOT/stub areas; one address per call; requires prior open_dsc). \
        Skips full auto-analysis.",
        output = "responses::DscAddRegionOutput",
        title = "Map a shared-cache address range",
        annotations(read_only = false, destructive = false, open_world = false),
        cli(positional = "address")
    )]
    #[instrument(skip_all, fields(address = ?req.address))]
    async fn dsc_add_region(
        &self,
        Parameters(req): Parameters<DscAddRegionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: dsc_add_region");

        let ea = match req.address.to_exactly_one("address") {
            Ok(value) => value,
            Err(ToolError::InvalidAddress(addr)) => {
                return Ok(
                    ToolError::InvalidParams(format!("Invalid address: {addr}")).to_tool_result()
                );
            }
            Err(e) => return Ok(e.to_tool_result()),
        };
        let ea_hex = format!("0x{ea:x}");
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(300)
        .min(MAX_TIMEOUT_SECS);
        match self.worker.dsc_load_region(ea, Some(timeout_secs)).await {
            Ok(region) => {
                let analysis_status = match self.worker.analysis_status().await {
                    Ok(status) => Some(status),
                    Err(err) => {
                        warn!(
                            address = %ea_hex,
                            error = %err,
                            "failed to fetch analysis_status after dsc_add_region"
                        );
                        None
                    }
                };
                let analysis_ready = analysis_status.as_ref().map(|s| s.auto_is_ok);
                let next_steps = dsc_analysis_next_steps(
                    analysis_ready,
                    "Proceed with xrefs/decompile/list_functions for symbols near this region.",
                );
                Ok(structured_json(json!({
                    "success": true,
                    "address": ea_hex,
                    "address_value": ea,
                    "message": format!(
                        "Successfully loaded DSC region at 0x{ea:x}. \
                         Full auto-analysis was not forced."
                    ),
                    "dsc_backend": "dscu",
                    "region": region,
                    "analysis_status": analysis_status,
                    "analysis_ready": analysis_ready,
                    "next_steps": next_steps,
                })))
            }
            Err(ToolError::Timeout(secs)) => {
                let message = format!(
                    "dsc_add_region timed out after {secs} seconds while loading region {ea_hex}"
                );
                warn!(
                    address = %ea_hex,
                    timeout_secs = secs,
                    "dsc_add_region timed out"
                );
                Ok(ToolError::IdaError(message).to_tool_result())
            }
            Err(ToolError::TimeoutDetailed(message)) => {
                warn!(
                    address = %ea_hex,
                    timeout_secs,
                    "dsc_add_region timed out"
                );
                Ok(ToolError::IdaError(format!(
                    "dsc_add_region timed out while loading region {ea_hex}: {message}"
                ))
                .to_tool_result())
            }
            Err(e) => Ok(e.to_tool_result()),
        }
    }

    #[tool(
        description = "Check the status of a background task (e.g. DSC loading). \
        Returns the current status: 'running' (with a progress message), \
        'completed' (with the result — database is already open), \
        'failed' (with an error message), or 'cancelled'. \
        Use the task_id returned by open_dsc.",
        output_schema = responses::schema::<responses::TaskStatusOutput>(),
        title = "Background task progress",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    #[instrument(skip_all)]
    async fn task_status(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<TaskStatusRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: task_status");

        let owner = self.task_owner(&ctx.meta);
        let state = match self.task_registry.get_for_owner(&owner, &req.task_id) {
            Some(s) => s,
            None => {
                return Ok(
                    ToolError::InvalidParams(format!("Unknown task_id: {}", req.task_id))
                        .to_tool_result(),
                );
            }
        };

        let elapsed = state.created_at.elapsed().as_secs();
        let status_str = match state.status {
            task::TaskStatus::Running => "running",
            task::TaskStatus::Completed => "completed",
            task::TaskStatus::Failed => "failed",
            task::TaskStatus::Cancelled => "cancelled",
        };

        let mut response = json!({
            "task_id": state.id,
            "status": status_str,
            "message": state.message,
            "elapsed_secs": elapsed,
        });

        if let Some(result) = &state.result
            && let Value::Object(map) = &mut response
        {
            map.insert("result".to_string(), result.clone());
        }

        Ok(structured_json(response))
    }

    #[vibrev_tool(
        description = "Inspect recent foreground operation history. \
        Returns the currently active foreground operation (if any) and the last \
        recorded phase transitions for open_idb, run_script, and analyze_funcs.",
        output = "RecentOperations",
        title = "Recent foreground operation log",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(no_session)
    )]
    async fn recent_operations(
        &self,
        Parameters(req): Parameters<RecentOperationsRequest>,
    ) -> Result<CallToolResult, McpError> {
        let recent: RecentOperations = self.operation_registry.recent(req.limit);
        Ok(structured_value(&recent, "recent_operations"))
    }

    #[tool(
        description = "Execute IDAPython in the open database. Provide 'code' (inline) \
        or 'file' (path to .py), not both. Returns captured stdout/stderr. \
        Full access to ida_*, idc, idautils.",
        output_schema = responses::schema::<responses::RunScriptOutput>(),
        title = "Run IDAPython inside the database",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            open_world_hint = true
        )
    )]
    #[instrument(skip_all, fields(code_len = req.code.as_ref().map_or(0, String::len)))]
    async fn run_script(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(req): Parameters<RunScriptRequest>,
    ) -> Result<CallToolResult, McpError> {
        let code = match (req.code, req.file) {
            (Some(code), None) => code,
            (None, Some(path)) => {
                if !Self::validate_path(&path) {
                    return Ok(ToolError::InvalidPath(path).to_tool_result());
                }
                match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(e) => {
                        return Ok(ToolError::InvalidPath(format!(
                            "Failed to read script file '{}': {}",
                            path, e
                        ))
                        .to_tool_result());
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' or 'file', not both".into(),
                )
                .to_tool_result());
            }
            (None, None) => {
                return Ok(ToolError::InvalidParams(
                    "Provide either 'code' (inline Python) or 'file' (path to .py)".into(),
                )
                .to_tool_result());
            }
        };
        let timeout = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .unwrap_or(120)
        .min(MAX_TIMEOUT_SECS);
        match self
            .run_foreground_operation(
                &ctx,
                "run_script",
                format!("code_len={}", code.len()),
                Some(timeout),
                120,
                |progress_tx, cancel| {
                    self.worker
                        .run_script_observed(&code, Some(progress_tx), Some(cancel))
                },
            )
            .await
        {
            Ok(result) => {
                if !run_script_succeeded(&result) {
                    let message = run_script_failure_message(&result);
                    warn!(code_len = code.len(), error = %message, "run_script failed");
                    return Ok(ToolError::IdaError(message).to_tool_result());
                }
                Ok(structured_json(result))
            }
            Err(ForegroundOperationError::TimedOut {
                timeout_secs,
                snapshot,
            }) => {
                let detail = run_script_timeout_message(timeout_secs, &code);
                warn!(timeout_secs, code_len = code.len(), "run_script timed out");
                Ok(ToolError::TimeoutDetailed(Self::operation_timeout_message(
                    "run_script",
                    timeout_secs,
                    &snapshot,
                    Some(detail),
                ))
                .to_tool_result())
            }
            Err(ForegroundOperationError::Cancelled { snapshot }) => Ok(ToolError::Cancelled(
                Self::operation_cancelled_message("run_script", &snapshot),
            )
            .to_tool_result()),
            Err(ForegroundOperationError::Tool(error)) => Ok(error.to_tool_result()),
        }
    }
}
