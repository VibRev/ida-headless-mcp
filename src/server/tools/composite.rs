#[vibrev_tool_router(
    router = composite_router,
    vis = "pub(crate)",
    defs = "composite_defs",
    cli = "composite_cli",
    call = "composite_call",
)]
impl IdaMcpServer {
    // =======================================================================
    // Composite tools
    // =======================================================================
    //
    // Two tools that answer a whole question in one call instead of making a
    // client discover the answer over five or ten round trips. The tool-design
    // convention requires both of them from every engine — a `*_survey` that
    // orients you in a binary you have never seen, and an `analyze_*` that
    // hands you a complete dossier on one target — and requires the two to
    // carry the same field names and the same meanings across engines, so the
    // response types in `responses.rs` are written as the cross-engine
    // baseline rather than as an IDA-shaped convenience.
    //
    // They are *compositions*, not a translation layer. Every value below
    // comes from a worker method that a primitive tool also calls; what these
    // add is ranking, bucketing, joining and truncation bookkeeping — work
    // that is cheap here and expensive for a client to do over the wire. When
    // a composite needs something the worker cannot answer, the fix is a new
    // worker capability, never a reinterpretation of an existing one.

    #[vibrev_tool(
        description = "Orient yourself in an unfamiliar binary with one call. Returns file \
        metadata, segment layout, entry points, whole-database counts, the strings ranked by \
        how often they are referenced, the functions ranked by references and size, the imports \
        bucketed into crypto/network/registry/process/file_io/memory/string/time by a naive \
        name heuristic, and a call-graph summary (roots, leaves, extremes). Replaces the \
        idb_meta + segments + entrypoints + list_funcs + strings + imports sequence. \
        Bounded by design so it cannot run away on a large image: at most 10000 functions, \
        5000 strings, 10000 imports and 10000 exported names are scanned, and the response's \
        `limits` block reports exactly what was covered and what was cut. The per-function \
        metrics pass (xrefs, callers, callees) is the expensive part — pass detail='minimal' \
        to skip it, which drops interesting_strings, interesting_functions and \
        callgraph_summary from the answer.",
        output = "responses::SurveyBinaryOutput",
        title = "First look at an unknown binary",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(detail = ?req.detail))]
    async fn survey_binary(
        &self,
        Parameters(req): Parameters<SurveyBinaryRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: survey_binary");

        let minimal = req.detail == Some(requests::SurveyDetail::Minimal);
        let max_functions = try_param!(parse_optional_unsigned::<usize>(
            req.max_functions,
            "max_functions"
        ))
        .unwrap_or(Self::MAX_SURVEY_FUNCTIONS)
        .clamp(1, Self::MAX_SURVEY_FUNCTIONS);
        let max_strings = try_param!(parse_optional_unsigned::<usize>(
            req.max_strings,
            "max_strings"
        ))
        .unwrap_or(Self::MAX_SURVEY_STRINGS)
        .min(Self::MAX_SURVEY_STRINGS);
        let max_imports = try_param!(parse_optional_unsigned::<usize>(
            req.max_imports,
            "max_imports"
        ))
        .unwrap_or(Self::MAX_SURVEY_IMPORTS)
        .min(Self::MAX_SURVEY_IMPORTS);
        let max_exports = try_param!(parse_optional_unsigned::<usize>(
            req.max_exports,
            "max_exports"
        ))
        .unwrap_or(Self::MAX_SURVEY_EXPORTS)
        .min(Self::MAX_SURVEY_EXPORTS);
        let top = try_param!(parse_optional_unsigned::<usize>(req.top, "top"))
            .unwrap_or(Self::DEFAULT_SURVEY_HIGHLIGHTS)
            .min(Self::MAX_SURVEY_HIGHLIGHTS);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        // Sampled ahead of the reads below, not after them: see
        // `IdaMcpServer::analysis_coverage`. This is the tool the coverage
        // block matters most for — every number in `statistics` and
        // `callgraph_summary` is a lower bound until analysis settles.
        let coverage = self.analysis_coverage().await;

        // Six bounded reads. Any of them failing means the database is not
        // usable, so they short-circuit rather than degrade.
        let meta = try_worker!(self.worker.idb_meta().await);
        let segments = try_worker!(self.worker.segments().await);
        let entry_addresses = try_worker!(self.worker.entrypoints().await);
        let functions = try_worker!(
            self.worker
                .list_functions(FunctionQuery::paged(0, max_functions), timeout_secs)
                .await
        );
        let strings = try_worker!(
            self.worker
                .strings(StringQuery::paged(0, max_strings), timeout_secs)
                .await
        );
        let imports = try_worker!(self.worker.imports(NameQuery::paged(0, max_imports)).await);
        let exports = try_worker!(self.worker.exports(NameQuery::paged(0, max_exports)).await);

        // The metrics pass is the only expensive step, and the only one that
        // degrades instead of failing: a survey without rankings still tells a
        // client what it is looking at. `SurveyMetrics` is a read-only member
        // of the SDK mutation enum — it counts references, it writes nothing —
        // which is why this tool stays annotated read-only.
        let mut metrics_error = None;
        let metrics = if minimal {
            None
        } else {
            let function_addresses = functions
                .functions
                .iter()
                .filter_map(|function| Self::parse_address(&function.address).ok())
                .collect::<Vec<_>>();
            let string_addresses = strings
                .strings
                .iter()
                .filter_map(|string| Self::parse_address(&string.address).ok())
                .collect::<Vec<_>>();
            match self
                .worker
                .sdk_mutation(SdkMutation::SurveyMetrics {
                    function_addresses,
                    string_addresses,
                })
                .await
            {
                Ok(value) => Some(value),
                Err(error) => {
                    warn!(error = %error, "survey_binary: metrics pass failed, degrading");
                    metrics_error = Some(error.to_string());
                    None
                }
            }
        };
        let function_metrics = survey_metric_index(metrics.as_ref(), "functions");
        let string_metrics = survey_metric_index(metrics.as_ref(), "strings");

        let min_address = meta_string(&meta, "min_address").unwrap_or_else(|| "0x0".to_string());
        let max_address = meta_string(&meta, "max_address").unwrap_or_else(|| min_address.clone());
        let image_size = Self::parse_address(&max_address)
            .ok()
            .zip(Self::parse_address(&min_address).ok())
            .map_or_else(
                || "0x0".to_string(),
                |(high, low)| format!("{:#x}", high.saturating_sub(low)),
            );
        let path = meta_string(&meta, "input_file_path").unwrap_or_default();
        let metadata = responses::SurveyMetadata {
            module: std::path::Path::new(&path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&path)
                .to_string(),
            path: path.clone(),
            file_type: meta_string(&meta, "file_type").unwrap_or_default(),
            processor: meta_string(&meta, "processor").unwrap_or_default(),
            bits: meta.get("bits").and_then(Value::as_u64).unwrap_or(0) as u32,
            base_address: meta_string(&meta, "base_address"),
            min_address,
            max_address,
            image_size,
            input_file_size: meta.get("input_file_size").and_then(Value::as_u64),
            md5: meta_string(&meta, "md5"),
            sha256: meta_string(&meta, "sha256"),
            main_address: meta_string(&meta, "main_address"),
        };

        let function_names = functions
            .functions
            .iter()
            .filter_map(|function| {
                Self::parse_address(&function.address)
                    .ok()
                    .map(|address| (address, function.name.clone()))
            })
            .collect::<std::collections::HashMap<_, _>>();
        let entrypoints = entry_addresses
            .iter()
            .enumerate()
            .map(|(ordinal, address)| responses::SurveyEntrypoint {
                name: Self::parse_address(address)
                    .ok()
                    .and_then(|address| function_names.get(&address).cloned()),
                address: address.clone(),
                ordinal,
            })
            .collect::<Vec<_>>();

        let unnamed_functions = functions
            .functions
            .iter()
            .filter(|function| function.name.starts_with("sub_"))
            .count();
        let statistics = responses::SurveyStatistics {
            total_functions: functions.total,
            named_functions: functions.functions.len().saturating_sub(unnamed_functions),
            unnamed_functions,
            total_strings: strings.total,
            total_segments: segments.len(),
            total_imports: imports.total,
            total_exports: exports.total,
            total_entrypoints: entry_addresses.len(),
        };

        let mut interesting_strings = None;
        let mut interesting_functions = None;
        let mut callgraph_summary = None;
        if metrics.is_some() {
            let mut ranked_strings = strings
                .strings
                .iter()
                .map(|string| responses::SurveyString {
                    xref_count: Self::parse_address(&string.address)
                        .ok()
                        .and_then(|address| string_metrics.get(&address))
                        .map_or(0, |metric| metric.xrefs),
                    address: string.address.clone(),
                    content: string.content.clone(),
                    length: string.length,
                })
                .collect::<Vec<_>>();
            // Most-referenced first; longer strings break ties because a long
            // string carries more signal than a two-character one at the same
            // reference count. Address last, purely for a stable order.
            ranked_strings.sort_by(|left, right| {
                right
                    .xref_count
                    .cmp(&left.xref_count)
                    .then_with(|| right.length.cmp(&left.length))
                    .then_with(|| left.address.cmp(&right.address))
            });
            ranked_strings.truncate(top);
            interesting_strings = Some(ranked_strings);

            let mut ranked_functions = functions
                .functions
                .iter()
                .map(|function| {
                    let metric = Self::parse_address(&function.address)
                        .ok()
                        .and_then(|address| function_metrics.get(&address).copied())
                        .unwrap_or_default();
                    responses::SurveyFunction {
                        address: function.address.clone(),
                        name: function.name.clone(),
                        size: function.size,
                        xref_count: metric.xrefs,
                        caller_count: metric.incoming_calls,
                        callee_count: metric.outgoing_calls,
                        kind: survey_function_kind(function.size, metric.outgoing_calls)
                            .to_string(),
                    }
                })
                .collect::<Vec<_>>();

            // Summarize before truncating: the shape of the call graph is a
            // property of everything that was scanned, not of the top 15.
            callgraph_summary = Some(responses::SurveyCallgraphSummary {
                total_call_edges: ranked_functions
                    .iter()
                    .map(|function| function.callee_count)
                    .sum(),
                root_function_count: ranked_functions
                    .iter()
                    .filter(|function| function.caller_count == 0)
                    .count(),
                root_functions: ranked_functions
                    .iter()
                    .filter(|function| function.caller_count == 0)
                    .take(top)
                    .map(|function| function.name.clone())
                    .collect(),
                leaf_function_count: ranked_functions
                    .iter()
                    .filter(|function| function.callee_count == 0)
                    .count(),
                max_out_degree: ranked_functions
                    .iter()
                    .max_by_key(|function| function.callee_count)
                    .map(|function| responses::SurveyFunctionDegree {
                        address: function.address.clone(),
                        name: function.name.clone(),
                        count: function.callee_count,
                    }),
                max_in_degree: ranked_functions
                    .iter()
                    .max_by_key(|function| function.caller_count)
                    .map(|function| responses::SurveyFunctionDegree {
                        address: function.address.clone(),
                        name: function.name.clone(),
                        count: function.caller_count,
                    }),
            });

            ranked_functions.sort_by(|left, right| {
                right
                    .xref_count
                    .cmp(&left.xref_count)
                    .then_with(|| right.size.cmp(&left.size))
                    .then_with(|| left.address.cmp(&right.address))
            });
            ranked_functions.truncate(top);
            interesting_functions = Some(ranked_functions);
        }

        let mut imports_by_category: std::collections::BTreeMap<
            String,
            Vec<responses::SurveyImport>,
        > = std::collections::BTreeMap::new();
        for import in &imports.imports {
            imports_by_category
                .entry(import_category(&import.name).to_string())
                .or_default()
                .push(responses::SurveyImport {
                    address: import.address.clone(),
                    name: import.name.clone(),
                    module: import.module.clone(),
                });
        }

        let output = responses::SurveyBinaryOutput {
            metadata,
            statistics,
            segments: segments.iter().map(responses::SegmentInfo::from).collect(),
            entrypoints,
            interesting_strings,
            interesting_functions,
            imports_by_category,
            callgraph_summary,
            limits: responses::SurveyLimits {
                detail: if minimal { "minimal" } else { "standard" }.to_string(),
                max_functions_scanned: max_functions,
                functions_scanned: functions.functions.len(),
                functions_truncated: functions.total > functions.functions.len(),
                max_strings_scanned: max_strings,
                strings_scanned: strings.strings.len(),
                strings_truncated: strings.total > strings.strings.len(),
                max_imports_scanned: max_imports,
                imports_scanned: imports.imports.len(),
                // `total` is the count the walk made, so the same comparison
                // the two listings above use applies here. `len() >=
                // max_imports` would only be a guess — "we got exactly as many
                // as we asked for, so there are probably more" — and it is
                // wrong precisely when the table has exactly `max_imports`
                // entries.
                imports_truncated: imports.total > imports.imports.len(),
                max_exports_scanned: max_exports,
                exports_scanned: exports.exports.len(),
                exports_truncated: exports.total > exports.exports.len(),
                highlight_limit: top,
                metrics_computed: metrics.is_some(),
                metrics_error,
            },
            analysis_coverage: coverage,
        };
        Ok(structured_value(&output, "survey_binary"))
    }

    #[vibrev_tool(
        description = "Everything about one function in a single call: disassembly, decompiler \
        pseudocode, callers, callees, the strings it references, its stack frame and its \
        control-flow graph. Accepts an address, several addresses, or a symbol name; any \
        address inside a function resolves to that function. Replaces the \
        function_at + decompile + disasm_function_at + callers + callees + stack_frame + \
        basic_blocks sequence, and subsumes what a separate batch tool would do. \
        Always answers with {results, limits} — one entry per target, in request order, even \
        for a single target. A section that fails does not fail the target: each block has a \
        sibling *_error and the rest still comes back. Bounded by design: at most 32 targets \
        per call, 5000 instructions per listing, 1000 callers, 1000 callees, 2000 basic blocks, \
        and a 5000-string index scan behind referenced_strings — turn that one off with \
        include_strings=false on string-heavy binaries.",
        output = "responses::AnalyzeFunctionOutput",
        title = "Complete dossier on one function",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(int_args = "offset")
    )]
    #[instrument(skip_all, fields(target_name = ?req.target_name))]
    async fn analyze_function(
        &self,
        Parameters(req): Parameters<AnalyzeFunctionRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_function");

        let offset = req.offset.unwrap_or(0);
        // A target is either an address (possibly several) or one symbol name.
        // Both go through `function_at`, which is the same resolver the
        // primitive tools use, so "an address in the middle of a function"
        // behaves identically here.
        let targets: Vec<(String, Option<u64>, Option<String>)> = match req.address.as_ref() {
            Some(value) => try_param!(value.to_addresses())
                .into_iter()
                .map(|address| (format!("{address:#x}"), Some(address), None))
                .collect(),
            None => match req.target_name.as_deref().map(str::trim) {
                Some(name) if !name.is_empty() => {
                    vec![(name.to_string(), None, Some(name.to_string()))]
                }
                _ => {
                    return Ok(ToolError::InvalidParams(
                        "analyze_function needs an address or a target_name".to_string(),
                    )
                    .to_tool_result());
                }
            },
        };
        let targets_truncated = targets.len() > Self::MAX_ANALYZE_TARGETS;

        let include_pseudocode = req.include_pseudocode.unwrap_or(true);
        let include_disassembly = req.include_disassembly.unwrap_or(true);
        let include_strings = req.include_strings.unwrap_or(true);
        let include_stack_frame = req.include_stack_frame.unwrap_or(true);
        let include_basic_blocks = req.include_basic_blocks.unwrap_or(true);
        let max_instructions = try_param!(parse_optional_unsigned::<usize>(
            req.max_instructions,
            "max_instructions"
        ))
        .unwrap_or(Self::DEFAULT_ANALYZE_INSTRUCTIONS)
        .min(Self::MAX_ANALYZE_INSTRUCTIONS);
        let max_callers = try_param!(parse_optional_unsigned::<usize>(
            req.max_callers,
            "max_callers"
        ))
        .unwrap_or(Self::DEFAULT_ANALYZE_RELATIVES)
        .min(Self::MAX_ANALYZE_RELATIVES);
        let max_callees = try_param!(parse_optional_unsigned::<usize>(
            req.max_callees,
            "max_callees"
        ))
        .unwrap_or(Self::DEFAULT_ANALYZE_RELATIVES)
        .min(Self::MAX_ANALYZE_RELATIVES);
        let max_blocks = try_param!(parse_optional_unsigned::<usize>(
            req.max_blocks,
            "max_blocks"
        ))
        .unwrap_or(Self::DEFAULT_ANALYZE_BLOCKS)
        .min(Self::MAX_ANALYZE_BLOCKS);
        let max_strings_scanned = try_param!(parse_optional_unsigned::<usize>(
            req.max_strings_scanned,
            "max_strings_scanned"
        ))
        .unwrap_or(Self::MAX_ANALYZE_STRINGS)
        .min(Self::MAX_ANALYZE_STRINGS);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ));

        // One scan of the string cross-reference index serves every target: it
        // is the reverse of what we want (string -> referrers), so intersecting
        // its referrer addresses with a function's range is the only bounded
        // way to answer "which strings does this function use" without walking
        // the function one instruction at a time.
        let mut strings_error = None;
        let string_index = if include_strings {
            match self
                .worker
                .xrefs_to_string(
                    StringSearch::scan(max_strings_scanned),
                    Self::ANALYZE_STRING_XREF_CAP,
                    timeout_secs,
                )
                .await
            {
                Ok(index) => Some(index),
                Err(error) => {
                    warn!(error = %error, "analyze_function: string index scan failed");
                    strings_error = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };

        let mut results = Vec::with_capacity(targets.len().min(Self::MAX_ANALYZE_TARGETS));
        for (target, address, name) in targets.into_iter().take(Self::MAX_ANALYZE_TARGETS) {
            let range = match self.worker.function_at(address, name, offset).await {
                Ok(range) => range,
                Err(error) => {
                    results.push(responses::AnalyzeFunctionEntry {
                        target,
                        error: Some(error.to_string()),
                        ..Default::default()
                    });
                    continue;
                }
            };
            let Ok(start) = Self::parse_address(&range.start) else {
                results.push(responses::AnalyzeFunctionEntry {
                    target,
                    error: Some(format!("unparseable function start '{}'", range.start)),
                    ..Default::default()
                });
                continue;
            };
            let end = Self::parse_address(&range.end).unwrap_or(start);

            let mut entry = responses::AnalyzeFunctionEntry {
                target,
                address: Some(range.address.clone()),
                name: Some(range.name.clone()),
                start: Some(range.start.clone()),
                end: Some(range.end.clone()),
                size: Some(range.size),
                ..Default::default()
            };

            if include_pseudocode {
                match self.worker.decompile(start).await {
                    Ok(code) => entry.pseudocode = Some(code),
                    Err(error) => entry.pseudocode_error = Some(error.to_string()),
                }
            }
            if include_disassembly {
                match self
                    .worker
                    .disasm_function_at(Some(start), None, 0, max_instructions)
                    .await
                {
                    Ok(listing) => entry.disassembly = Some(listing),
                    Err(error) => entry.disassembly_error = Some(error.to_string()),
                }
            }
            match self.worker.callers(start).await {
                Ok(callers) => {
                    entry.caller_count = Some(callers.len());
                    entry.callers_truncated = Some(callers.len() > max_callers);
                    entry.callers = Some(
                        callers
                            .iter()
                            .take(max_callers)
                            .map(responses::FunctionInfo::from)
                            .collect(),
                    );
                }
                Err(error) => entry.callers_error = Some(error.to_string()),
            }
            match self.worker.callees(start).await {
                Ok(callees) => {
                    entry.callee_count = Some(callees.len());
                    entry.callees_truncated = Some(callees.len() > max_callees);
                    entry.callees = Some(
                        callees
                            .iter()
                            .take(max_callees)
                            .map(responses::FunctionInfo::from)
                            .collect(),
                    );
                }
                Err(error) => entry.callees_error = Some(error.to_string()),
            }
            if include_stack_frame {
                match self.worker.stack_frame(start).await {
                    Ok(frame) => entry.stack_frame = Some((&frame).into()),
                    Err(error) => entry.stack_frame_error = Some(error.to_string()),
                }
            }
            if include_basic_blocks {
                match self.worker.basic_blocks(start).await {
                    Ok(blocks) => {
                        entry.basic_block_count = Some(blocks.len());
                        entry.basic_blocks_truncated = Some(blocks.len() > max_blocks);
                        entry.basic_blocks = Some(
                            blocks
                                .iter()
                                .take(max_blocks)
                                .map(responses::BasicBlockInfo::from)
                                .collect(),
                        );
                    }
                    Err(error) => entry.basic_blocks_error = Some(error.to_string()),
                }
            }
            if let Some(index) = string_index.as_ref() {
                entry.referenced_strings = Some(
                    index
                        .strings
                        .iter()
                        .filter_map(|string| {
                            let referenced_from = string
                                .xrefs
                                .iter()
                                .filter(|xref| {
                                    Self::parse_address(xref)
                                        .is_ok_and(|from| from >= start && from < end)
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            (!referenced_from.is_empty()).then(|| responses::FunctionStringRef {
                                address: string.address.clone(),
                                content: string.content.clone(),
                                length: string.length,
                                referenced_from,
                            })
                        })
                        .collect(),
                );
            }

            results.push(entry);
        }

        let output = responses::AnalyzeFunctionOutput {
            limits: responses::AnalyzeFunctionLimits {
                max_targets: Self::MAX_ANALYZE_TARGETS,
                targets_analyzed: results.len(),
                targets_truncated,
                max_instructions,
                max_callers,
                max_callees,
                max_blocks,
                max_strings_scanned,
                strings_scanned: string_index.as_ref().map_or(0, |index| index.strings.len()),
                strings_truncated: string_index
                    .as_ref()
                    .is_some_and(|index| index.total > index.strings.len()),
                strings_error,
            },
            results,
        };
        Ok(structured_value(&output, "analyze_function"))
    }

    #[vibrev_tool(
        description = "Analyze related functions as a group: compact per-function summaries, \
        the internal call graph, shared globals, and interface vs internal functions. Accepts \
        names or addresses (list, single value, or comma-separated). Does not decompile and \
        does not return a full disassembly. Any token that cannot be resolved fails the whole \
        call. Bounded: at most 32 functions, 5 strings per summary, and data xrefs collected \
        from function/basic-block starts (not every instruction).",
        output = "responses::AnalyzeComponentOutput",
        title = "Related functions as a group",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all)]
    async fn analyze_component(
        &self,
        Parameters(req): Parameters<AnalyzeComponentRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: analyze_component");

        let tokens = match req.addrs.as_ref() {
            Some(value) => try_param!(Self::value_to_strings(value)),
            None => {
                return Ok(ToolError::InvalidParams(
                    "analyze_component needs addrs (function names or addresses)".to_string(),
                )
                .to_tool_result());
            }
        };
        if tokens.is_empty() {
            return Ok(ToolError::InvalidParams("Empty address list".to_string()).to_tool_result());
        }

        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .map(|secs| secs.min(MAX_TIMEOUT_SECS));

        let coverage = self.analysis_coverage().await;

        let mut resolved = Vec::with_capacity(tokens.len());
        let mut seen = std::collections::HashSet::new();
        for token in tokens {
            let range = match Self::parse_address(&token) {
                Ok(addr) => self.worker.function_at(Some(addr), None, 0).await,
                Err(_) => self.worker.function_at(None, Some(token.clone()), 0).await,
            };
            let range = match range {
                Ok(range) => range,
                Err(_) => {
                    return Ok(ToolError::InvalidParams(format!(
                        "Cannot resolve address: {token:?}"
                    ))
                    .to_tool_result());
                }
            };
            let start = match Self::parse_address(&range.start) {
                Ok(start) => start,
                Err(_) => {
                    return Ok(ToolError::InvalidParams(format!(
                        "Cannot resolve address: {token:?}"
                    ))
                    .to_tool_result());
                }
            };
            if !seen.insert(start) {
                continue;
            }
            let end = Self::parse_address(&range.end).unwrap_or(start);
            resolved.push((start, end, range));
        }
        let targets_truncated = resolved.len() > Self::MAX_ANALYZE_TARGETS;
        resolved.truncate(Self::MAX_ANALYZE_TARGETS);

        let mut strings_error = None;
        let string_index = match self
            .worker
            .xrefs_to_string(
                StringSearch::scan(Self::MAX_ANALYZE_STRINGS),
                Self::ANALYZE_STRING_XREF_CAP,
                timeout_secs,
            )
            .await
        {
            Ok(index) => Some(index),
            Err(error) => {
                warn!(error = %error, "analyze_component: string index scan failed");
                strings_error = Some(error.to_string());
                None
            }
        };

        struct ComponentFn {
            start: u64,
            name: String,
            size: usize,
            callees: Vec<crate::ida::types::FunctionInfo>,
            callers: Vec<crate::ida::types::FunctionInfo>,
            blocks: Vec<crate::ida::types::BasicBlockInfo>,
            all_strings: Vec<String>,
            globals: std::collections::BTreeSet<u64>,
        }

        let component_starts: Vec<u64> = resolved.iter().map(|(start, _, _)| *start).collect();
        let component_set: std::collections::HashSet<u64> =
            component_starts.iter().copied().collect();

        let mut analyzed = Vec::with_capacity(resolved.len());
        let mut data_xrefs_truncated = false;
        let mut global_class: std::collections::HashMap<u64, bool> =
            std::collections::HashMap::new();

        for (start, end, range) in resolved {
            let callees = match self.worker.callees(start).await {
                Ok(callees) => callees,
                Err(error) => {
                    warn!(error = %error, start, "analyze_component: callees failed");
                    Vec::new()
                }
            };
            let callers = match self.worker.callers(start).await {
                Ok(callers) => callers,
                Err(error) => {
                    warn!(error = %error, start, "analyze_component: callers failed");
                    Vec::new()
                }
            };
            let blocks = match self.worker.basic_blocks(start).await {
                Ok(blocks) => blocks,
                Err(error) => {
                    warn!(error = %error, start, "analyze_component: basic_blocks failed");
                    Vec::new()
                }
            };

            let mut xref_sites = Vec::new();
            xref_sites.push(start);
            for block in &blocks {
                if let Ok(block_start) = Self::parse_address(&block.start)
                    && block_start != start
                    && !xref_sites.contains(&block_start)
                {
                    xref_sites.push(block_start);
                }
            }

            let mut globals = std::collections::BTreeSet::new();
            for site in xref_sites {
                match self
                    .worker
                    .xrefs_from(site, XrefQuery::paged(0, Self::MAX_COMPONENT_DATA_XREFS), timeout_secs)
                    .await
                {
                    Ok(page) => {
                        if page.truncated {
                            data_xrefs_truncated = true;
                        }
                        for xref in page.xrefs {
                            if xref.is_code {
                                continue;
                            }
                            let Ok(to) = Self::parse_address(&xref.to) else {
                                continue;
                            };
                            let is_global = if let Some(known) = global_class.get(&to) {
                                *known
                            } else {
                                let classified =
                                    match self.worker.function_at(Some(to), None, 0).await {
                                        Ok(owner) => match (
                                            Self::parse_address(&owner.start),
                                            Self::parse_address(&owner.end),
                                        ) {
                                            (Ok(owner_start), Ok(owner_end)) => {
                                                to < owner_start || to >= owner_end
                                            }
                                            _ => true,
                                        },
                                        Err(_) => true,
                                    };
                                global_class.insert(to, classified);
                                classified
                            };
                            if is_global {
                                globals.insert(to);
                            }
                        }
                    }
                    Err(error) => {
                        warn!(
                            error = %error,
                            site,
                            "analyze_component: xrefs_from at block start failed"
                        );
                    }
                }
            }

            let all_strings = string_index
                .as_ref()
                .map(|index| {
                    index
                        .strings
                        .iter()
                        .filter(|string| {
                            string.xrefs.iter().any(|xref| {
                                Self::parse_address(xref)
                                    .is_ok_and(|from| from >= start && from < end)
                            })
                        })
                        .map(|string| string.content.clone())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            analyzed.push(ComponentFn {
                start,
                name: range.name,
                size: range.size,
                callees,
                callers,
                blocks,
                all_strings,
                globals,
            });
        }

        let mut call_refs = Vec::new();
        for func in &analyzed {
            for callee in &func.callees {
                if let Ok(to) = Self::parse_address(&callee.address) {
                    call_refs.push((func.start, to, callee.name.as_str()));
                }
            }
        }
        let internal_call_graph = component_internal_call_graph(&component_starts, &call_refs);

        let mut functions = Vec::with_capacity(analyzed.len());
        let mut interface_functions = Vec::new();
        let mut internal_only = Vec::new();
        let mut string_funcs: std::collections::BTreeMap<
            String,
            std::collections::BTreeSet<String>,
        > = std::collections::BTreeMap::new();
        let mut global_accessors: std::collections::BTreeMap<
            u64,
            std::collections::BTreeSet<String>,
        > = std::collections::BTreeMap::new();

        for func in &analyzed {
            let addr = format!("{:#x}", func.start);
            let has_external =
                func.callers
                    .iter()
                    .any(|caller| match Self::parse_address(&caller.address) {
                        Ok(caller_addr) => !component_set.contains(&caller_addr),
                        Err(_) => true,
                    });
            if has_external {
                interface_functions.push(addr.clone());
            } else {
                internal_only.push(addr.clone());
            }

            for content in &func.all_strings {
                if !content.is_empty() {
                    string_funcs
                        .entry(content.clone())
                        .or_default()
                        .insert(func.name.clone());
                }
            }
            for global in &func.globals {
                global_accessors
                    .entry(*global)
                    .or_default()
                    .insert(func.name.clone());
            }

            let edge_count = func
                .blocks
                .iter()
                .map(|block| block.successors.len())
                .sum::<usize>();

            functions.push(responses::ComponentFunctionSummary {
                addr,
                name: func.name.clone(),
                size: func.size,
                callees: func
                    .callees
                    .iter()
                    .map(|callee| responses::ComponentCallee {
                        addr: callee.address.clone(),
                        name: callee.name.clone(),
                    })
                    .collect(),
                strings: compact_component_strings(
                    func.all_strings.iter(),
                    Self::MAX_COMPONENT_STRINGS,
                ),
                basic_blocks: func.blocks.len(),
                complexity: cyclomatic_complexity(func.blocks.len(), edge_count),
            });
        }

        let string_usage = string_funcs
            .into_iter()
            .filter(|(_, names)| names.len() >= 2)
            .map(|(content, names)| (content, names.into_iter().collect()))
            .collect();

        let mut shared_globals = Vec::new();
        for (addr, accessors) in global_accessors {
            if accessors.len() < 2 {
                continue;
            }
            let name = match self.worker.addr_info(Some(addr), None, 0).await {
                Ok(info) => info
                    .symbol
                    .filter(|symbol| symbol.exact)
                    .map(|symbol| symbol.name)
                    .unwrap_or_else(|| format!("{addr:#x}")),
                Err(_) => format!("{addr:#x}"),
            };
            shared_globals.push(responses::SharedGlobal {
                addr: format!("{addr:#x}"),
                name,
                accessed_by: accessors.into_iter().collect(),
            });
        }

        let output = responses::AnalyzeComponentOutput {
            functions,
            internal_call_graph,
            shared_globals,
            interface_functions,
            internal_only,
            string_usage,
            limits: responses::AnalyzeComponentLimits {
                max_targets: Self::MAX_ANALYZE_TARGETS,
                targets_analyzed: analyzed.len(),
                targets_truncated,
                max_strings_per_function: Self::MAX_COMPONENT_STRINGS,
                max_strings_scanned: Self::MAX_ANALYZE_STRINGS,
                strings_scanned: string_index.as_ref().map_or(0, |index| index.strings.len()),
                strings_truncated: string_index
                    .as_ref()
                    .is_some_and(|index| index.total > index.strings.len()),
                strings_error,
                max_data_xrefs_per_site: Self::MAX_COMPONENT_DATA_XREFS,
                data_xrefs_truncated,
            },
            analysis_coverage: coverage.clone(),
        };
        Ok(structured_with_coverage(
            &output,
            &coverage,
            "analyze_component",
        ))
    }

    #[vibrev_tool(
        description = "Rename a function, apply a prototype, or set a comment, then compare \
        Hex-Rays output before and after. Resolves an address or name to the enclosing \
        function. A failed edit is an error; a failed decompile is reported in \
        before_error/after_error and does not fail the call.",
        output = "responses::DiffBeforeAfterOutput",
        title = "Side-by-side decompile after an edit",
        annotations(read_only = false, destructive = false, open_world = false)
    )]
    #[instrument(skip_all, fields(action = ?req.action, target_name = ?req.target_name))]
    async fn diff_before_after(
        &self,
        Parameters(req): Parameters<DiffBeforeAfterRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: diff_before_after");

        let addr = match req.address.as_ref() {
            Some(value) => Some(try_param!(value.to_single())),
            None => None,
        };
        let target_name = req
            .target_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string);
        if addr.is_none() && target_name.is_none() {
            return Ok(ToolError::InvalidParams(
                "diff_before_after needs an address or a target_name".to_string(),
            )
            .to_tool_result());
        }

        let (new_name, decl, comment) = match req.action {
            DiffAction::RenameFunc => {
                let name = req
                    .name
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(str::to_string);
                let Some(name) = name else {
                    return Ok(ToolError::InvalidParams(
                        "diff_before_after rename_func needs name".to_string(),
                    )
                    .to_tool_result());
                };
                (Some(name), None, None)
            }
            DiffAction::SetType => {
                let decl = req
                    .decl
                    .as_deref()
                    .map(str::trim)
                    .filter(|decl| !decl.is_empty())
                    .map(str::to_string);
                let Some(decl) = decl else {
                    return Ok(ToolError::InvalidParams(
                        "diff_before_after set_type needs decl".to_string(),
                    )
                    .to_tool_result());
                };
                (None, Some(decl), None)
            }
            DiffAction::SetComment => {
                let Some(comment) = req.comment.clone() else {
                    return Ok(ToolError::InvalidParams(
                        "diff_before_after set_comment needs comment".to_string(),
                    )
                    .to_tool_result());
                };
                (None, None, Some(comment))
            }
        };

        let range = match self.worker.function_at(addr, target_name, 0).await {
            Ok(range) => range,
            Err(error) => return Ok(error.to_tool_result()),
        };
        let start = match Self::parse_address(&range.start) {
            Ok(start) => start,
            Err(_) => {
                return Ok(ToolError::InvalidParams(format!(
                    "unparseable function start '{}'",
                    range.start
                ))
                .to_tool_result());
            }
        };

        let (before, before_error) = match self.worker.decompile(start).await {
            Ok(code) => (Some(code), None),
            Err(error) => (None, Some(error.to_string())),
        };

        match req.action {
            DiffAction::RenameFunc => {
                if let Err(error) = self
                    .worker
                    .rename(Some(start), None, new_name.expect("validated"), 0)
                    .await
                {
                    return Ok(error.to_tool_result());
                }
            }
            DiffAction::SetType => {
                let result = match self
                    .worker
                    .apply_types(crate::ida::ApplyTypesSpec {
                        addr: Some(start),
                        decl: Some(decl.expect("validated")),
                        strict: true,
                        ..Default::default()
                    })
                    .await
                {
                    Ok(result) => result,
                    Err(error) => return Ok(error.to_tool_result()),
                };
                if let Some(reason) = type_mutation_failure(&result) {
                    return Ok(structured_failure(
                        &result,
                        "diff_before_after",
                        format!(
                            "diff_before_after did not apply the type: {reason}. Nothing was changed."
                        ),
                    ));
                }
            }
            DiffAction::SetComment => {
                if let Err(error) = self
                    .worker
                    .set_comments(Some(start), None, 0, comment.expect("validated"), false)
                    .await
                {
                    return Ok(error.to_tool_result());
                }
            }
        }

        let mut action_error = None;
        if let Err(error) = self
            .worker
            .sdk_mutation(SdkMutation::MarkCfuncDirty { address: start })
            .await
        {
            warn!(error = %error, start, "diff_before_after: mark_cfunc_dirty failed");
            action_error = Some(error.to_string());
        }

        let (after, after_error) = match self.worker.decompile(start).await {
            Ok(code) => (Some(code), None),
            Err(error) => (None, Some(error.to_string())),
        };
        let changes_detected =
            matches!((&before, &after), (Some(left), Some(right)) if left != right);

        let output = responses::DiffBeforeAfterOutput {
            address: format!("{start:#x}"),
            name: range.name,
            action: req.action,
            action_applied: true,
            before,
            after,
            changes_detected,
            before_error,
            after_error,
            action_error,
        };
        Ok(structured_value(&output, "diff_before_after"))
    }

    #[vibrev_tool(
        description = "Walk xrefs forward (xrefs_from) or backward (xrefs_to) from one address \
        by BFS. This is a data-reference trace, not a call graph. Each node is one address \
        with its instruction and enclosing function; hops are capped at 20 depth, 200 nodes \
        and 500 edges.",
        output = "responses::TraceDataFlowOutput",
        title = "Multi-hop xref walk",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        ),
        cli(positional = "address")
    )]
    #[instrument(skip_all)]
    async fn trace_data_flow(
        &self,
        Parameters(req): Parameters<TraceDataFlowRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: trace_data_flow");

        let start = try_param!(req.address.to_exactly_one("address"));
        let direction = trace_direction_or_default(req.direction);
        let max_depth = clamp_trace_max_depth(req.max_depth);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .map(|secs| secs.min(MAX_TIMEOUT_SECS));

        let coverage = self.analysis_coverage().await;

        let mut visited = std::collections::HashSet::new();
        visited.insert(start);
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((start, 0usize));

        let mut nodes = Vec::new();
        nodes.push(self.trace_data_flow_node(start, 0).await);
        let mut edges = Vec::new();
        let mut depth_reached = 0usize;
        let mut nodes_truncated = false;
        let mut edges_truncated = false;
        let mut xrefs_truncated = false;

        while let Some((current, depth)) = queue.pop_front() {
            depth_reached = depth_reached.max(depth);
            if depth >= max_depth {
                continue;
            }

            let page = match direction {
                TraceDirection::Forward => {
                    self.worker
                        .xrefs_from(current, XrefQuery::paged(0, Self::TRACE_XREFS_PER_NODE), timeout_secs)
                        .await
                }
                TraceDirection::Backward => {
                    self.worker
                        .xrefs_to(current, XrefQuery::paged(0, Self::TRACE_XREFS_PER_NODE), timeout_secs)
                        .await
                }
            };
            let page = match page {
                Ok(page) => page,
                Err(error) => {
                    warn!(error = %error, current, "trace_data_flow: xref page failed");
                    continue;
                }
            };
            if page.truncated {
                xrefs_truncated = true;
            }

            let hops: Vec<TraceXrefHop> = page
                .xrefs
                .iter()
                .filter_map(|xref| {
                    Some(TraceXrefHop {
                        from: Self::parse_address(&xref.from).ok()?,
                        to: Self::parse_address(&xref.to).ok()?,
                        is_code: xref.is_code,
                    })
                })
                .collect();
            let (new_edges, next_addrs) = trace_data_flow_step(current, direction, &hops, &visited);

            for hop in new_edges {
                if edges.len() >= Self::TRACE_MAX_EDGES {
                    edges_truncated = true;
                    break;
                }
                edges.push(responses::TraceDataFlowEdge {
                    from: format!("{:#x}", hop.from),
                    to: format!("{:#x}", hop.to),
                    r#type: if hop.is_code {
                        responses::TraceRefKind::Code
                    } else {
                        responses::TraceRefKind::Data
                    },
                });
            }

            for neighbor in next_addrs {
                if nodes.len() >= Self::TRACE_MAX_NODES {
                    nodes_truncated = true;
                    break;
                }
                if !visited.insert(neighbor) {
                    continue;
                }
                nodes.push(self.trace_data_flow_node(neighbor, depth + 1).await);
                queue.push_back((neighbor, depth + 1));
            }
        }

        let output = responses::TraceDataFlowOutput {
            start: format!("{start:#x}"),
            direction,
            depth_reached,
            nodes,
            edges,
            limits: responses::TraceDataFlowLimits {
                max_depth,
                max_nodes: Self::TRACE_MAX_NODES,
                max_edges: Self::TRACE_MAX_EDGES,
                nodes_truncated,
                edges_truncated,
                xrefs_truncated,
            },
            analysis_coverage: coverage.clone(),
        };
        Ok(structured_with_coverage(
            &output,
            &coverage,
            "trace_data_flow",
        ))
    }

    async fn trace_data_flow_node(&self, addr: u64, depth: usize) -> responses::TraceDataFlowNode {
        let info = self.worker.addr_info(Some(addr), None, 0).await.ok();
        let instruction = self.worker.disasm(addr, 1).await.ok();
        let func = info
            .as_ref()
            .and_then(|info| info.function.as_ref())
            .map(|function| function.name.clone());
        let name = info.as_ref().and_then(|info| {
            info.symbol
                .as_ref()
                .map(|symbol| symbol.name.clone())
                .or_else(|| info.function.as_ref().map(|function| function.name.clone()))
        });
        let kind = if func.is_some() {
            responses::TraceRefKind::Code
        } else {
            responses::TraceRefKind::Data
        };
        responses::TraceDataFlowNode {
            addr: format!("{addr:#x}"),
            func,
            instruction,
            r#type: kind,
            name,
            depth,
        }
    }

    #[vibrev_tool(
        description = "A cheaper look at one function than analyze_function: callers, callees, \
        basic blocks, cyclomatic complexity and string refs, with no decompile and no \
        instruction listing. Address may be a list; a name selects one function. \
        include_lists=false (the default) returns counts only.",
        output = "responses::FuncProfileOutput",
        title = "Cheap single-function summary",
        annotations(
            read_only = true,
            destructive = false,
            idempotent = true,
            open_world = false
        )
    )]
    #[instrument(skip_all, fields(target_name = ?req.target_name))]
    async fn func_profile(
        &self,
        Parameters(req): Parameters<FuncProfileRequest>,
    ) -> Result<CallToolResult, McpError> {
        debug!("Tool call: func_profile");

        let targets: Vec<(String, Option<u64>, Option<String>)> = match req.address.as_ref() {
            Some(value) => try_param!(value.to_addresses())
                .into_iter()
                .map(|address| (format!("{address:#x}"), Some(address), None))
                .collect(),
            None => match req.target_name.as_deref().map(str::trim) {
                Some(name) if !name.is_empty() => {
                    vec![(name.to_string(), None, Some(name.to_string()))]
                }
                _ => {
                    return Ok(ToolError::InvalidParams(
                        "func_profile needs an address or a target_name".to_string(),
                    )
                    .to_tool_result());
                }
            },
        };
        let targets_truncated = targets.len() > Self::MAX_ANALYZE_TARGETS;
        let include_lists = req.include_lists.unwrap_or(false);
        let max_items = try_param!(parse_optional_unsigned::<usize>(req.max_items, "max_items"))
            .unwrap_or(Self::DEFAULT_PROFILE_ITEMS)
            .min(Self::MAX_PROFILE_ITEMS);
        let timeout_secs = try_param!(parse_optional_unsigned::<u64>(
            req.timeout_secs,
            "timeout_secs"
        ))
        .map(|secs| secs.min(MAX_TIMEOUT_SECS));

        let coverage = self.analysis_coverage().await;

        let mut strings_error = None;
        let string_index = match self
            .worker
            .xrefs_to_string(
                StringSearch::scan(Self::MAX_ANALYZE_STRINGS),
                Self::ANALYZE_STRING_XREF_CAP,
                timeout_secs,
            )
            .await
        {
            Ok(index) => Some(index),
            Err(error) => {
                warn!(error = %error, "func_profile: string index scan failed");
                strings_error = Some(error.to_string());
                None
            }
        };

        let mut results = Vec::with_capacity(targets.len().min(Self::MAX_ANALYZE_TARGETS));
        for (target, address, name) in targets.into_iter().take(Self::MAX_ANALYZE_TARGETS) {
            let range = match self.worker.function_at(address, name, 0).await {
                Ok(range) => range,
                Err(error) => {
                    results.push(responses::FuncProfileEntry {
                        target,
                        error: Some(error.to_string()),
                        ..Default::default()
                    });
                    continue;
                }
            };
            let Ok(start) = Self::parse_address(&range.start) else {
                results.push(responses::FuncProfileEntry {
                    target,
                    error: Some(format!("unparseable function start '{}'", range.start)),
                    ..Default::default()
                });
                continue;
            };
            let end = Self::parse_address(&range.end).unwrap_or(start);

            let mut entry = responses::FuncProfileEntry {
                target,
                address: Some(format!("{start:#x}")),
                name: Some(range.name),
                size: Some(range.size),
                ..Default::default()
            };

            match self.worker.callers(start).await {
                Ok(callers) => {
                    entry.caller_count = Some(callers.len());
                    if include_lists {
                        entry.callers_truncated = Some(callers.len() > max_items);
                        entry.callers = Some(
                            callers
                                .iter()
                                .take(max_items)
                                .map(responses::FunctionInfo::from)
                                .collect(),
                        );
                    }
                }
                Err(error) => {
                    warn!(error = %error, start, "func_profile: callers failed");
                }
            }
            match self.worker.callees(start).await {
                Ok(callees) => {
                    entry.callee_count = Some(callees.len());
                    if include_lists {
                        entry.callees_truncated = Some(callees.len() > max_items);
                        entry.callees = Some(
                            callees
                                .iter()
                                .take(max_items)
                                .map(responses::FunctionInfo::from)
                                .collect(),
                        );
                    }
                }
                Err(error) => {
                    warn!(error = %error, start, "func_profile: callees failed");
                }
            }
            match self.worker.basic_blocks(start).await {
                Ok(blocks) => {
                    let edge_count = blocks.iter().map(|block| block.successors.len()).sum();
                    entry.basic_block_count = Some(blocks.len());
                    entry.complexity = Some(cyclomatic_complexity(blocks.len(), edge_count));
                }
                Err(error) => {
                    warn!(error = %error, start, "func_profile: basic_blocks failed");
                }
            }
            if let Some(index) = string_index.as_ref() {
                let contents: Vec<String> = index
                    .strings
                    .iter()
                    .filter(|string| {
                        string.xrefs.iter().any(|xref| {
                            Self::parse_address(xref).is_ok_and(|from| from >= start && from < end)
                        })
                    })
                    .map(|string| string.content.clone())
                    .collect();
                entry.string_ref_count = Some(contents.len());
                if include_lists {
                    entry.strings_truncated = Some(contents.len() > max_items);
                    entry.strings = Some(contents.into_iter().take(max_items).collect());
                }
            }

            results.push(entry);
        }

        let output = responses::FuncProfileOutput {
            limits: responses::FuncProfileLimits {
                max_targets: Self::MAX_ANALYZE_TARGETS,
                targets_analyzed: results.len(),
                targets_truncated,
                max_items,
                max_strings_scanned: Self::MAX_ANALYZE_STRINGS,
                strings_scanned: string_index.as_ref().map_or(0, |index| index.strings.len()),
                strings_truncated: string_index
                    .as_ref()
                    .is_some_and(|index| index.total > index.strings.len()),
                strings_error,
            },
            results,
            analysis_coverage: coverage.clone(),
        };
        Ok(structured_with_coverage(&output, &coverage, "func_profile"))
    }
}
