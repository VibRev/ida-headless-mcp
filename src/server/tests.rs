use crate::error::ToolError;
use crate::ida::worker::CloseTokenGrant;
use crate::server::{
    apply_close_metadata, bounded_scan_ceiling, clamp_trace_max_depth, close_hint_for,
    compact_component_strings, component_internal_call_graph, cyclomatic_complexity, dsc_open_plan,
    import_category, is_sessionless_request_meta, meta_string,
    operation::{OperationSnapshot, OperationStatus},
    paginate_bounded_matches, run_script_failure_message, run_script_succeeded,
    run_script_timeout_message, structured_failure, supported_protocol_versions,
    survey_function_kind, survey_metric_index, task, tool_annotations_for, tool_title_for,
    trace_data_flow_step, trace_direction_or_default, type_mutation_failure, AddressArg,
    AnalyzeComponentRequest, DiffBeforeAfterRequest, DscOpenPlan, FuncProfileRequest, IdaMcpServer,
    OpenIdbBackgroundDecision, RecentOperationsRequest, ServerRuntimeState, ToolCatalogRequest,
    ToolHelpRequest, TraceDirection, TraceXrefHop, XrefsRequest,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, InputResponses, ProtocolVersion};
use rmcp::ServerHandler;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use vibrev_kit::tasks::TaskHost;

const TASK_OWNER: task::TaskOwner = task::TaskOwner::Runtime;

fn addr_arg(value: Value) -> AddressArg {
    serde_json::from_value(value).expect("valid AddressArg")
}

#[test]
fn a_bounded_scan_looks_one_hit_past_the_page() {
    // A ceiling of exactly offset + limit is what makes `total` come back equal
    // to `limit` and `next_offset` unreachable, so the scan looks one hit past.
    assert_eq!(bounded_scan_ceiling(0, 100, None), 101);
    assert_eq!(bounded_scan_ceiling(100, 50, None), 151);
    // Never past the hard ceiling.
    assert_eq!(bounded_scan_ceiling(0, 10_000_000, None), 20000);
    assert_eq!(bounded_scan_ceiling(usize::MAX, 10, None), 20000);
    // `_worker_max_results` replaces the calculation outright.
    assert_eq!(bounded_scan_ceiling(0, 100, Some(7)), 7);
}

#[test]
fn a_full_page_with_more_behind_it_advances() {
    let hits = (0..101).map(|i| json!(format!("{i:#x}"))).collect();

    let page = paginate_bounded_matches(hits, 0, 100, 101);

    assert_eq!(page.matches.len(), 100);
    assert_eq!(page.next_offset, Some(100));
    // 101 hits seen under a ceiling of 101: the scan stopped early.
    assert_eq!(page.total, 101);
    assert!(page.total_is_lower_bound);
}

#[test]
fn a_page_that_exhausts_the_database_reports_the_real_total() {
    let hits = (0..27).map(|i| json!(format!("{i:#x}"))).collect();

    let page = paginate_bounded_matches(hits, 0, 100, 101);

    assert_eq!(page.matches.len(), 27);
    assert_eq!(page.total, 27);
    assert!(!page.total_is_lower_bound);
    assert_eq!(page.next_offset, None);
}

#[test]
fn the_last_page_of_a_paged_scan_stops() {
    let hits = (0..27).map(|i| json!(format!("{i:#x}"))).collect();

    let page = paginate_bounded_matches(hits, 20, 10, 31);

    assert_eq!(page.matches.len(), 7);
    assert_eq!(page.next_offset, None);
    assert!(!page.total_is_lower_bound);
}

#[test]
fn a_scan_stopped_by_the_ceiling_never_invents_a_next_page() {
    // Everything the scan saw fits in the page, and there is nothing past
    // it to advance into — but the answer is still incomplete, and
    // `total_is_lower_bound` is the field that says so.
    let hits = (0..20000).map(|i| json!(format!("{i:#x}"))).collect();

    let page = paginate_bounded_matches(hits, 0, 20000, 20000);

    assert_eq!(page.next_offset, None);
    assert!(page.total_is_lower_bound);

    // An offset beyond the ceiling yields an empty page rather than a
    // next_offset that never moves.
    let hits = (0..20000).map(|i| json!(format!("{i:#x}"))).collect();
    let page = paginate_bounded_matches(hits, 25000, 100, 20000);
    assert!(page.matches.is_empty());
    assert_eq!(page.next_offset, None);
}

#[test]
fn a_failed_type_mutation_is_recognised_in_either_arm() {
    // declare_stack / delete_stack / apply_types(stack arm)
    assert_eq!(
        type_mutation_failure(&json!({"code": -5, "status": "error"})).as_deref(),
        Some("IDA returned code -5")
    );
    // apply_types(address arm)
    assert_eq!(
        type_mutation_failure(&json!({"applied": false, "source": "decl"})).as_deref(),
        Some("IDA rejected the type")
    );
    // declare_type(multi = true)
    assert_eq!(
        type_mutation_failure(&json!({"errors": 3})).as_deref(),
        Some("3 declaration(s) did not parse")
    );

    for success in [
        json!({"code": 0, "status": "ok"}),
        json!({"applied": true, "source": "named"}),
        json!({"errors": 0}),
    ] {
        assert_eq!(type_mutation_failure(&success), None, "{success}");
    }
}

#[test]
fn a_failed_mutation_sets_is_error_and_keeps_its_payload() {
    let payload = json!({
        "function": "0x2000",
        "name": "y",
        "offset": -8,
        "code": -5,
        "status": "error",
    });

    let result = structured_failure(
        &payload,
        "declare_stack",
        "declare_stack did not define the stack variable: IDA returned code -5".to_string(),
    );

    // A client that reads only `isError` — which the MCP spec says is
    // enough — must see the failure.
    assert_eq!(result.is_error, Some(true));
    assert_eq!(result.structured_content, Some(payload));
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
        .unwrap_or_default();
    assert!(text.contains("code -5"), "{text}");
}

#[test]
fn mutation_failure_messages_never_carry_lifecycle_phrases() {
    // `crate::ida::remote::classify_child_error` reads the child's message
    // by substring, so a failure message that happened to contain one of
    // these would arrive at the caller as a timeout or a cancellation and
    // the pool would act on it. The messages are built from numbers, but
    // pin the property so a future edit cannot quietly interpolate a name.
    for reason in [
        type_mutation_failure(&json!({"code": -5})).unwrap(),
        type_mutation_failure(&json!({"applied": false})).unwrap(),
        type_mutation_failure(&json!({"errors": 2})).unwrap(),
    ] {
        let lowered = reason.to_ascii_lowercase();
        for phrase in [
            "worker channel closed",
            "timed out after",
            "operation timed out",
            "exceeded worker operation timeout",
            "cancelled",
            "canceled",
        ] {
            assert!(!lowered.contains(phrase), "{reason:?} contains {phrase:?}");
        }
    }
}

/// In-memory writer so a test can assert on exactly what the fmt layer
/// would have written to stderr, span field prefixes included.
#[derive(Clone, Default)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLog {
    fn text(&self) -> String {
        let guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        String::from_utf8_lossy(&guard).into_owned()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `body` with a thread-local subscriber at `directives` and return
/// everything it logged. `set_default` keeps this off the global
/// dispatcher, so tests stay independent.
async fn capture_logs<F, Fut>(directives: &str, body: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    let captured = CapturedLog::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(captured.clone())
            .with_filter(tracing_subscriber::EnvFilter::new(directives)),
    );
    let _guard = tracing::subscriber::set_default(subscriber);
    body().await;
    captured.text()
}

fn test_server() -> IdaMcpServer {
    let (tx, _rx) = mpsc::sync_channel(1);
    IdaMcpServer::new(
        Arc::new(crate::IdaWorker::new(tx)),
        crate::ServerMode::Stdio,
    )
}

/// Sentinels chosen so a substring hit can only come from the payload we
/// passed in, never from incidental log text.
const SECRET_CLOSE_TOKEN: &str = "close-token-9d41f2c7";
const SECRET_COMMENT: &str = "comment-secret-3a7f11de";
const SECRET_RENAME: &str = "rename-secret-5c2b90aa";
const SECRET_PATCH_BYTES: &str = "de ad be ef ca fe 41 42";

/// Drive every unit-invocable handler that receives sensitive payloads.
/// Each call fails fast (the test worker has no receiver), which is
/// exactly the path that logs — spans render whenever an event fires
/// inside them.
async fn exercise_sensitive_handlers(server: &IdaMcpServer) {
    let _ = server
        .close_idb(Parameters(crate::server::CloseIdbRequest {
            save: None,
            token: Some(SECRET_CLOSE_TOKEN.to_string()),
            force: Some(false),
        }))
        .await;
    let _ = server
        .set_comments(Parameters(crate::server::SetCommentsRequest {
            address: Some(addr_arg(json!("0x1000"))),
            target_name: None,
            offset: None,
            comment: SECRET_COMMENT.to_string(),
            repeatable: None,
        }))
        .await;
    let _ = server
        .rename(Parameters(crate::server::RenameRequest {
            address: Some(addr_arg(json!("0x1000"))),
            current_name: None,
            name: SECRET_RENAME.to_string(),
            flags: None,
        }))
        .await;
    let _ = server
        .patch(Parameters(crate::server::PatchRequest {
            address: Some(addr_arg(json!("0x1000"))),
            target_name: None,
            offset: None,
            bytes: json!(SECRET_PATCH_BYTES),
        }))
        .await;
}

fn assert_no_secrets(logs: &str, level: &str) {
    for (label, secret) in [
        ("close_idb ownership token", SECRET_CLOSE_TOKEN),
        ("set_comments payload", SECRET_COMMENT),
        ("rename payload", SECRET_RENAME),
        ("patch bytes", SECRET_PATCH_BYTES),
    ] {
        assert!(
            !logs.contains(secret),
            "{label} leaked into logs at {level}:\n{logs}"
        );
    }
    // The whole-struct render is the mechanism behind every leak; catching
    // it directly means a future handler cannot regress quietly.
    for struct_render in [
        "CloseIdbRequest {",
        "SetCommentsRequest {",
        "RenameRequest {",
        "PatchRequest {",
        "req=",
    ] {
        assert!(
            !logs.contains(struct_render),
            "a handler argument was recorded ({struct_render}) at {level}:\n{logs}"
        );
    }
}

/// The shipped default is `ida_mcp=info`, and `close_idb` logs at INFO
/// unconditionally — so before this fix the ownership bearer token
/// rendered on an out-of-the-box server, not just under trace logging.
#[tokio::test]
async fn spans_never_record_secret_payloads_at_the_shipped_level() {
    let server = test_server();
    let logs = capture_logs("ida_mcp=info", || async {
        exercise_sensitive_handlers(&server).await;
    })
    .await;

    // Positive control: prove the capture is wired and the level admits
    // output, so the absence assertions below cannot pass vacuously.
    assert!(
        logs.contains("Tool call: close_idb received"),
        "expected close_idb to log at ida_mcp=info; got:\n{logs}"
    );
    assert_no_secrets(&logs, "ida_mcp=info");
    assert!(
        logs.contains("has_token=true"),
        "expected the sanitized has_token field; got:\n{logs}"
    );
}

/// Strictly stronger than the shipped level, and the level `just test-*`
/// recipes run at: nothing sensitive may appear even at trace.
#[tokio::test]
async fn spans_never_record_secret_payloads_at_trace() {
    let server = test_server();
    let logs = capture_logs("ida_mcp=trace", || async {
        exercise_sensitive_handlers(&server).await;
    })
    .await;

    assert!(
        logs.contains("Tool call: close_idb received"),
        "expected handler events at trace; got:\n{logs}"
    );
    assert_no_secrets(&logs, "ida_mcp=trace");
}

/// Reassemble every `#[instrument(...)]` attribute in a source file,
/// joining continuation lines by paren balance.
fn instrument_attributes(source: &str) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut current: Option<(String, i32)> = None;
    for line in source.lines() {
        let trimmed = line.trim();
        let start = current.is_none() && trimmed.starts_with("#[instrument");
        if start || current.is_some() {
            let (mut text, mut depth) = current.take().unwrap_or_default();
            text.push_str(trimmed);
            depth += i32::try_from(trimmed.matches('(').count()).unwrap_or(0);
            depth -= i32::try_from(trimmed.matches(')').count()).unwrap_or(0);
            if depth <= 0 {
                attributes.push(text);
            } else {
                current = Some((text, depth));
            }
        }
    }
    attributes
}

/// `skip_all` is the only form that suppresses handler arguments:
/// tracing-attributes records every parameter binding via `Debug`, and a
/// `fields(...)` entry only suppresses a parameter whose ident exactly
/// matches the field name — so `fields(path = %req.path)` still records
/// the whole `req`. This is the only coverage for handlers that take a
/// `RequestContext` (`open_idb`, `run_script`) since `Peer`'s constructor
/// is `pub(crate)` and they cannot be invoked from a unit test.
#[test]
fn instrument_attributes_never_capture_handler_arguments() {
    let mut tool_handler_attrs = 0usize;
    for (path, source) in [
        ("src/server/mod.rs", include_str!("mod.rs")),
        ("src/server/tools.rs", include_str!("tools.rs")),
        (
            "src/server/tools/database.rs",
            include_str!("tools/database.rs"),
        ),
        (
            "src/server/tools/composite.rs",
            include_str!("tools/composite.rs"),
        ),
        (
            "src/server/tools/functions.rs",
            include_str!("tools/functions.rs"),
        ),
        (
            "src/server/tools/metadata.rs",
            include_str!("tools/metadata.rs"),
        ),
        (
            "src/server/tools/memory.rs",
            include_str!("tools/memory.rs"),
        ),
        ("src/server/tools/xrefs.rs", include_str!("tools/xrefs.rs")),
        (
            "src/server/tools/controlflow.rs",
            include_str!("tools/controlflow.rs"),
        ),
        ("src/server/tools/types.rs", include_str!("tools/types.rs")),
        (
            "src/server/tools/editing.rs",
            include_str!("tools/editing.rs"),
        ),
        (
            "src/server/http_sessions.rs",
            include_str!("http_sessions.rs"),
        ),
    ] {
        let attributes = instrument_attributes(source);
        for attribute in &attributes {
            assert!(
                attribute.contains("skip_all"),
                "{path}: `{attribute}` must use skip_all; \
                 skip(self) still records every request argument"
            );
        }
        if path.starts_with("src/server/tools/") {
            tool_handler_attrs += attributes.len();
        }
    }
    assert!(
        tool_handler_attrs >= 50,
        "expected the full handler set under src/server/tools/, found {tool_handler_attrs}"
    );
}

/// The two handlers that cannot be exercised at runtime must expose only
/// derived facts, never the sensitive binding itself.
#[test]
fn uninvokable_handlers_record_only_derived_fields() {
    let attributes = instrument_attributes(include_str!("tools/database.rs"));

    let open_idb = attributes
        .iter()
        .find(|attribute| attribute.contains("mrtr_retry"))
        .expect("open_idb should record whether this is an MRTR retry");
    // A bool derived from the sealed state, never the replayable handle
    // or the raw elicitation answers.
    assert!(open_idb.contains("request_state.is_some()"), "{open_idb}");
    assert!(!open_idb.contains("%request_state"), "{open_idb}");
    assert!(!open_idb.contains("?request_state"), "{open_idb}");
    assert!(!open_idb.contains("input_responses"), "{open_idb}");

    let run_script = attributes
        .iter()
        .find(|attribute| attribute.contains("code_len"))
        .expect("run_script should record only the source length");
    assert!(!run_script.contains("%req.code"), "{run_script}");
    assert!(!run_script.contains("?req.code"), "{run_script}");
}

/// A task ID is a bearer capability, so writing one to a log hands it to
/// whoever can read the log.
///
/// The registry itself is `vibrev_kit::tasks` and is not scanned here — it
/// cannot fail this test, because the kit has no tracing dependency at all and
/// so has nothing to log with. What is scanned is everything on this side that
/// *does* log and *does* handle an ID.
#[test]
fn tracing_never_records_task_bearer_ids() {
    let bearer_field = ["task", "id"].join("_");
    for (path, source) in [
        ("src/server/mod.rs", include_str!("mod.rs")),
        ("src/server/tools.rs", include_str!("tools.rs")),
        (
            "src/server/tools/database.rs",
            include_str!("tools/database.rs"),
        ),
        (
            "src/server/tools/composite.rs",
            include_str!("tools/composite.rs"),
        ),
        (
            "src/server/tools/functions.rs",
            include_str!("tools/functions.rs"),
        ),
        (
            "src/server/tools/metadata.rs",
            include_str!("tools/metadata.rs"),
        ),
        (
            "src/server/tools/memory.rs",
            include_str!("tools/memory.rs"),
        ),
        ("src/server/tools/xrefs.rs", include_str!("tools/xrefs.rs")),
        (
            "src/server/tools/controlflow.rs",
            include_str!("tools/controlflow.rs"),
        ),
        ("src/server/tools/types.rs", include_str!("tools/types.rs")),
        (
            "src/server/tools/editing.rs",
            include_str!("tools/editing.rs"),
        ),
    ] {
        for formatter in ['%', '?'] {
            let forbidden = format!("{bearer_field} = {formatter}");
            assert!(
                !source.contains(&forbidden),
                "{path}: task bearer IDs must not be recorded by tracing: found `{forbidden}`"
            );
        }
        for level in ["trace", "debug", "info", "warn", "error"] {
            let forbidden = format!("{level}!({bearer_field}");
            assert!(
                !source.contains(&forbidden),
                "{path}: task bearer IDs must not be recorded by tracing: found `{forbidden}`"
            );
        }

        for attribute in instrument_attributes(source) {
            assert!(
                !attribute.contains(&bearer_field),
                "{path}: task bearer IDs must not be recorded by instrumentation: `{attribute}`"
            );
        }
    }
}

fn xrefs_request(limit: Option<i64>, offset: Option<i64>) -> XrefsRequest {
    XrefsRequest {
        address: addr_arg(json!("0x1000")),
        limit,
        offset,
        kind: None,
        dedup: None,
        include_function: None,
        timeout_secs: None,
    }
}

#[test]
fn xrefs_paging_clamps_zero_limit_to_one() {
    // limit 0 would yield an empty-but-truncated page whose next_offset never
    // advances; the parser must clamp it so pagination always progresses.
    let (offset, limit, _) =
        IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(0), None)).unwrap();
    assert_eq!(offset, 0);
    assert_eq!(limit, 1);
}

#[test]
fn xrefs_paging_applies_default_and_upper_bound() {
    let (_, default_limit, _) =
        IdaMcpServer::parse_xrefs_paging(&xrefs_request(None, Some(7))).unwrap();
    assert_eq!(default_limit, IdaMcpServer::DEFAULT_XREFS_LIMIT);

    let (offset, capped_limit, _) =
        IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(999_999), Some(7))).unwrap();
    assert_eq!(offset, 7);
    assert_eq!(capped_limit, IdaMcpServer::MAX_XREFS_LIMIT);
}

/// A negative `offset` is refused; a negative `limit` is clamped like a zero.
///
/// Refusing both would put this tool at odds with `bn-headless-mcp`, which
/// clamps a negative page size, and with the test above, which requires a
/// `limit` of 0 to become 1. Zero and minus one are the same kind of answer to
/// "how many": not a size. Clamping one while refusing the other is a
/// distinction with nothing behind it.
///
/// `offset` is refused for its own reason: -1 is not entry 0, and silently
/// serving the first page tells a caller whose arithmetic is wrong that it was
/// right.
#[test]
fn xrefs_paging_refuses_a_negative_offset_and_clamps_a_negative_limit() {
    let (_, limit, _) =
        IdaMcpServer::parse_xrefs_paging(&xrefs_request(Some(-1), None)).expect("clamped");
    assert_eq!(limit, 1);
    assert!(IdaMcpServer::parse_xrefs_paging(&xrefs_request(None, Some(-1))).is_err());
}

#[test]
fn dsc_open_plan_backgrounds_ida_94_raw_dsc() {
    assert_eq!(
        dsc_open_plan((9, 4), false),
        DscOpenPlan::BackgroundDirectRawDsc
    );
    assert_eq!(
        dsc_open_plan((10, 0), false),
        DscOpenPlan::BackgroundDirectRawDsc
    );
}

#[test]
fn dsc_open_plan_keeps_legacy_idat_for_pre_94_raw_dsc() {
    assert_eq!(
        dsc_open_plan((9, 3), false),
        DscOpenPlan::LegacyIdatBackground
    );
    assert_eq!(
        dsc_open_plan((8, 4), false),
        DscOpenPlan::LegacyIdatBackground
    );
}

/// An existing database wins on every SDK: it preserves prior analysis
/// and, on 9.4, prevents the direct path from minting a fresh multi-GB
/// database per open_dsc call.
#[test]
fn dsc_open_plan_prefers_existing_i64_on_every_sdk() {
    assert_eq!(dsc_open_plan((9, 3), true), DscOpenPlan::DirectExistingI64);
    assert_eq!(dsc_open_plan((9, 4), true), DscOpenPlan::DirectExistingI64);
    assert_eq!(dsc_open_plan((10, 0), true), DscOpenPlan::DirectExistingI64);
}

/// The direct-path database name must depend only on the DSC's absolute
/// path — never pid or time — so repeat opens resolve to one reusable
/// file instead of accumulating orphans.
#[test]
fn direct_dsc_cache_path_is_deterministic_per_dsc() {
    let dsc = std::path::Path::new("/nonexistent/A/dyld_shared_cache_arm64e");
    let first = crate::server::direct_dsc_cache_i64_path(dsc);
    let second = crate::server::direct_dsc_cache_i64_path(dsc);
    let other = crate::server::direct_dsc_cache_i64_path(std::path::Path::new(
        "/nonexistent/B/dyld_shared_cache_arm64e",
    ));

    assert_eq!(first, second);
    assert_ne!(first, other, "different DSC paths must not collide");
    let name = first
        .file_name()
        .and_then(|name| name.to_str())
        .expect("cache path should have a printable file name");
    assert!(name.starts_with("ida-mcp-dsc-dyld_shared_cache_arm64e-"));
    assert!(name.ends_with(".i64"));
}

fn tool_result_text(result: CallToolResult) -> String {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.to_string())
        .unwrap_or_default()
}

#[test]
fn run_script_succeeded_only_for_explicit_true() {
    assert!(run_script_succeeded(&json!({ "success": true })));
    assert!(!run_script_succeeded(&json!({ "success": false })));
    assert!(!run_script_succeeded(&json!({})));
}

#[test]
fn run_script_failure_message_adds_syntax_hint() {
    let value = json!({
        "success": false,
        "stdout": "",
        "stderr": "Traceback (most recent call last):\n  File \"<string>\", line 1\nSyntaxError: invalid syntax",
        "error": "invalid syntax"
    });
    let message = run_script_failure_message(&value);
    assert!(message.contains("IDAPython script execution failed"));
    assert!(message.contains("SyntaxError"));
    assert!(message.contains("Hint: Python syntax error detected"));
}

#[test]
fn run_script_timeout_message_includes_preview() {
    let code = "import idaapi\nfor _ in range(1000000000):\n    pass\n";
    let message = run_script_timeout_message(120, code);
    assert!(message.contains("run_script timed out after 120 seconds"));
    assert!(message.contains("Script preview: import idaapi for _ in range(1000000000): pass"));
}

#[test]
fn operation_timeout_message_includes_phase_snapshot() {
    let snapshot = OperationSnapshot {
        op_id: "fg-1".to_string(),
        tool: "open_idb".to_string(),
        target_summary: "/tmp/sample.i64".to_string(),
        phase: "opening".to_string(),
        status: OperationStatus::TimedOut,
        message: "open_idb timed out".to_string(),
        started_at_ms: 1,
        last_update_ms: 2,
        elapsed_ms: 3456,
    };
    let message = IdaMcpServer::operation_timeout_message(
        "open_idb",
        300,
        &snapshot,
        Some("detail".to_string()),
    );
    assert!(message.contains("Last known phase: opening"));
    assert!(message.contains("Operation id: fg-1"));
    assert!(message.contains("detail"));
}

#[tokio::test]
async fn foreground_cancel_cleanup_polls_cancelled_future() {
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let observed = Arc::new(AtomicBool::new(false));
    let observed_for_future = observed.clone();
    let future = async move {
        cancel.cancelled().await;
        observed_for_future.store(true, Ordering::SeqCst);
        Err::<(), ToolError>(ToolError::Cancelled("cancelled".to_string()))
    };
    tokio::pin!(future);

    IdaMcpServer::finish_cancelled_foreground("test_tool", future.as_mut()).await;

    assert!(observed.load(Ordering::SeqCst));
}

#[test]
fn input_size_above_threshold_is_strictly_greater_than_threshold() {
    let threshold = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES;
    let exact_path =
        create_sparse_test_file("exact-threshold", threshold).expect("create exact file");
    let above_path =
        create_sparse_test_file("above-threshold", threshold + 1).expect("create above file");

    assert_eq!(
        IdaMcpServer::input_size_above_threshold(
            exact_path.to_str().expect("exact path should be UTF-8")
        ),
        None
    );

    let above_path_text = above_path.to_str().expect("above path should be UTF-8");
    assert_eq!(
        IdaMcpServer::input_size_above_threshold(&format!(" {above_path_text} ")),
        Some(threshold + 1)
    );

    let _ = std::fs::remove_file(exact_path);
    let _ = std::fs::remove_file(above_path);
}

#[test]
fn is_database_path_matches_existing_ida_database_extensions() {
    assert!(IdaMcpServer::is_database_path(" /tmp/sample.I64 "));
    assert!(IdaMcpServer::is_database_path("/tmp/sample.idb"));
    assert!(IdaMcpServer::is_database_path("/tmp/sample.id0"));
    assert!(!IdaMcpServer::is_database_path("/tmp/sample.macho"));
    assert!(!IdaMcpServer::is_database_path("/tmp/sample"));
}

#[test]
fn open_idb_elicitation_timeout_is_bounded_by_prompt_and_request_timeouts() {
    assert_eq!(
        IdaMcpServer::open_idb_elicitation_timeout_secs(None),
        crate::server::OPEN_IDB_ELICITATION_TIMEOUT_SECS
    );
    assert_eq!(
        IdaMcpServer::open_idb_elicitation_timeout_secs(Some(10)),
        10
    );
    assert_eq!(
        IdaMcpServer::open_idb_elicitation_timeout_secs(Some(600)),
        crate::server::OPEN_IDB_ELICITATION_TIMEOUT_SECS
    );
}

#[tokio::test]
async fn recent_operations_tool_reports_queued_active_operation() {
    let server = test_server();
    server.operation_registry.start(
        "fg-test".to_string(),
        "open_idb",
        "/tmp/sample.i64".to_string(),
    );

    let result = server
        .recent_operations(Parameters(RecentOperationsRequest { limit: Some(5) }))
        .await
        .expect("recent_operations call should succeed");
    let value: serde_json::Value =
        serde_json::from_str(&tool_result_text(result)).expect("recent_operations JSON");

    assert_eq!(value["active_operation"]["op_id"], "fg-test");
    assert_eq!(value["active_operation"]["phase"], "queued");
    assert_eq!(value["recent_events"][0]["tool"], "open_idb");
}

#[tokio::test]
async fn tool_help_and_catalog_include_recent_operations() {
    let server = test_server();

    let help_result = server
        .tool_help(Parameters(ToolHelpRequest {
            name: "recent_operations".to_string(),
        }))
        .await
        .expect("tool_help should succeed");
    let help_value: serde_json::Value =
        serde_json::from_str(&tool_result_text(help_result)).expect("tool_help JSON");
    assert_eq!(help_value["name"], "recent_operations");
    assert!(help_value["parameters"].get("properties").is_some());
    assert!(help_value["parameters"]["properties"]
        .get("limit")
        .is_some());

    let catalog_result = server
        .tool_catalog(Parameters(ToolCatalogRequest {
            query: Some("recent operation history".to_string()),
            category: None,
            limit: Some(5),
        }))
        .await
        .expect("tool_catalog should succeed");
    let catalog_value: serde_json::Value =
        serde_json::from_str(&tool_result_text(catalog_result)).expect("tool_catalog JSON");
    let tools = catalog_value["tools"]
        .as_array()
        .expect("tool_catalog tools array");
    assert!(tools
        .iter()
        .any(|tool| tool.get("name") == Some(&json!("recent_operations"))));
}

/// This server offers every version it can speak, and nothing clips the list
/// per backend: the sessionless 2026 lifecycle has to reach the wire alongside
/// the session-bound ones, because a client that speaks only 2026 negotiates
/// against exactly this list.
#[test]
fn every_supported_protocol_version_is_offered() {
    let offered = supported_protocol_versions();
    assert!(offered.contains(&ProtocolVersion::V_2026_07_28));
    assert!(offered.contains(&ProtocolVersion::V_2025_11_25));
}

#[test]
fn server_advertises_tasks_extension() {
    assert!(ServerHandler::get_info(&test_server())
        .capabilities
        .supports_tasks());
}

/// A tool that ran and reported failure has a *completed* task. The registry
/// and the payload shaping are the kit's; what this pins is that this engine
/// stores its own `ToolError` through the seam that keeps `isError: true` on
/// the wire, instead of collapsing it into a JSON-RPC error the client cannot
/// tell from a dropped connection.
#[test]
fn tool_error_is_a_completed_task_result_not_a_json_rpc_failure() {
    let registry = task::TaskRegistry::new();
    let id = registry
        .create_keyed(&TASK_OWNER, "dsc", "tool-error", "Opening DSC")
        .expect("create task");
    let error_result =
        ToolError::OpenFailed("idat exited with code 4".to_string()).to_tool_result();
    registry.complete(&id, task::call_tool_result_to_value(&error_result));

    let state = registry.get(&id).expect("task state");
    let value = serde_json::to_value(task::detailed_task(state, task::DEFAULT_POLL_INTERVAL_MS))
        .expect("serialize task");

    assert_eq!(value["status"], "completed");
    assert_eq!(value["result"]["isError"], true);
    assert!(value["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|text| text.contains("idat exited with code 4")));
    assert!(value.get("error").is_none());
}

/// The `tasks/*` verbs read *this server's* registry, resolved through *this
/// server's* owner rule.
///
/// The kit proves the verbs behave; nothing there can catch a `TaskHost` impl
/// wired to the wrong registry, which would answer "unknown task_id" for every
/// task the server itself created.
#[test]
fn the_tasks_face_is_bound_to_this_servers_own_registry() {
    let server = test_server();
    let meta = rmcp::model::RequestMetaObject::new();
    let id = server
        .task_registry()
        .create_keyed(&server.task_owner(&meta), "dsc", "bound", "Opening DSC")
        .expect("create task");

    let answer = server
        .serve_get_task(rmcp::model::GetTaskParams::new(id.clone()), &meta)
        .expect("the creating owner must be able to poll its own task");
    assert_eq!(answer.task.task.task_id, id);
    assert_eq!(answer.task.task.status, rmcp::model::TaskStatus::Working);
}

#[test]
fn runtime_state_survives_handler_recreation() {
    let (tx, _rx) = mpsc::sync_channel(1);
    let backend = Arc::new(crate::IdaWorker::new(tx));
    let filter = Arc::new(vibrev_kit::policy::ToolPolicy::unrestricted());
    let runtime = ServerRuntimeState::new();
    let first = IdaMcpServer::with_filter_and_state(
        backend.clone(),
        crate::ServerMode::Http,
        filter.clone(),
        runtime.clone(),
    );
    let second =
        IdaMcpServer::with_filter_and_state(backend, crate::ServerMode::Http, filter, runtime);
    let id = first
        .task_registry
        .create_keyed(
            &first.session_task_owner,
            "task",
            "shared-runtime",
            "Working",
        )
        .expect("create task");
    first.task_registry.complete(&id, json!({"ok": true}));

    assert!(second.task_registry.get(&id).is_some());
    assert!(Arc::ptr_eq(
        &first.runtime_lifetime,
        &second.runtime_lifetime
    ));
    // Each handler owns its own session lifetime so that dropping a legacy
    // session's handler cancels only that session's background tasks.
    assert!(!Arc::ptr_eq(
        &first.session_lifetime,
        &second.session_lifetime
    ));
}

#[test]
fn shared_runtime_keeps_legacy_task_ownership_session_scoped() {
    let (tx, _rx) = mpsc::sync_channel(1);
    let backend = Arc::new(crate::IdaWorker::new(tx));
    let filter = Arc::new(vibrev_kit::policy::ToolPolicy::unrestricted());
    let runtime = ServerRuntimeState::new();
    let first = IdaMcpServer::with_filter_and_state(
        backend.clone(),
        crate::ServerMode::Http,
        filter.clone(),
        runtime.clone(),
    );
    let second =
        IdaMcpServer::with_filter_and_state(backend, crate::ServerMode::Http, filter, runtime);

    let task_id = first
        .task_registry
        .create_keyed(
            &first.session_task_owner,
            "dsc",
            "/tmp/shared-cache",
            "Opening DSC",
        )
        .expect("first session should create the task");
    assert_eq!(
        second.task_registry.create_keyed(
            &second.session_task_owner,
            "dsc",
            "/tmp/shared-cache",
            "Opening DSC",
        ),
        Err(task::TaskCreateError::ExistingTaskIdIsPrivate)
    );
    assert!(
        second
            .task_registry
            .get_for_owner(&second.session_task_owner, &task_id)
            .is_none(),
        "another legacy session must not poll the task"
    );
    assert!(!second
        .task_registry
        .cancel_for_owner(&second.session_task_owner, &task_id));
    assert!(first
        .task_registry
        .get_for_owner(&first.session_task_owner, &task_id)
        .is_some());
}

#[test]
fn handler_drop_cancels_session_background_tasks_only() {
    let (tx, _rx) = mpsc::sync_channel(1);
    let backend = Arc::new(crate::IdaWorker::new(tx));
    let filter = Arc::new(vibrev_kit::policy::ToolPolicy::unrestricted());
    let runtime = ServerRuntimeState::new();
    let server = IdaMcpServer::with_filter_and_state(
        backend,
        crate::ServerMode::Http,
        filter,
        runtime.clone(),
    );

    let legacy_meta = rmcp::model::RequestMetaObject::new();
    let mut sessionless_meta = rmcp::model::RequestMetaObject::new();
    sessionless_meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    sessionless_meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());

    let session_token = server.background_lifetime(&legacy_meta).child_token();
    let runtime_token = server.background_lifetime(&sessionless_meta).child_token();
    drop(server);

    // Legacy session close (= handler drop) cancels the session's tasks...
    assert!(session_token.is_cancelled());
    // ...but sessionless MCP 2026 tasks outlive their per-request handler.
    assert!(!runtime_token.is_cancelled());

    drop(runtime);
    assert!(runtime_token.is_cancelled());
}

/// Under `--stateless`, rmcp drops the handler after every request even
/// for legacy protocol versions, so legacy requests must also use the
/// shared runtime owner and lifetime — otherwise their background tasks
/// would be cancelled on response and owned by an unreachable session ID.
#[test]
fn stateless_http_routes_legacy_requests_to_the_runtime_owner() {
    let (tx, _rx) = mpsc::sync_channel(1);
    let backend = Arc::new(crate::IdaWorker::new(tx));
    let filter = Arc::new(vibrev_kit::policy::ToolPolicy::unrestricted());
    let runtime = ServerRuntimeState::new_stateless_http();
    let server = IdaMcpServer::with_filter_and_state(
        backend,
        crate::ServerMode::Http,
        filter,
        runtime.clone(),
    );

    let legacy_meta = rmcp::model::RequestMetaObject::new();
    assert_eq!(server.task_owner(&legacy_meta), task::TaskOwner::Runtime);
    let background_token = server.background_lifetime(&legacy_meta).child_token();
    drop(server);
    assert!(
        !background_token.is_cancelled(),
        "stateless-mode tasks must outlive their per-request handler"
    );

    drop(runtime);
    assert!(background_token.is_cancelled());
}

#[test]
fn sessionless_meta_predicate_requires_complete_2026_key_set() {
    let mut meta = rmcp::model::RequestMetaObject::new();
    assert!(!is_sessionless_request_meta(&meta));

    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    assert!(!is_sessionless_request_meta(&meta));

    meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());
    assert!(is_sessionless_request_meta(&meta));

    // rmcp routes on key completeness, not the declared version: a legacy
    // version with the full key set still dispatches sessionless.
    let mut legacy_declared = rmcp::model::RequestMetaObject::new();
    legacy_declared.set_protocol_version(ProtocolVersion::V_2025_11_25);
    legacy_declared.set_client_capabilities(rmcp::model::ClientCapabilities::default());
    assert!(is_sessionless_request_meta(&legacy_declared));
}

#[test]
fn legacy_stdio_task_owner_stays_stable_when_request_metadata_changes() {
    let server = test_server();
    let mut full_meta = rmcp::model::RequestMetaObject::new();
    full_meta.set_protocol_version(ProtocolVersion::V_2025_11_25);
    full_meta.set_client_capabilities(rmcp::model::ClientCapabilities::default());
    let empty_meta = rmcp::model::RequestMetaObject::new();

    let task_id = server
        .task_registry
        .create_keyed(
            &server.task_owner(&full_meta),
            "analyze",
            "stdio-owner-regression",
            "Working",
        )
        .expect("full-metadata request should create a task");

    assert!(
        server
            .task_registry
            .get_for_owner(&server.task_owner(&empty_meta), &task_id)
            .is_some(),
        "later requests on the same stdio connection must retain ownership"
    );
    assert!(std::ptr::eq(
        server.background_lifetime(&full_meta),
        server.background_lifetime(&empty_meta)
    ));
}

#[test]
fn modern_open_idb_mrtr_is_bound_and_integrity_checked() {
    let server = test_server();
    let path = "/tmp/large-macho";
    let size = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES + 1;
    let first = server
        .modern_open_idb_background_decision(path, size, None, None)
        .expect("first MRTR round");
    let OpenIdbBackgroundDecision::InputRequired(input_required) = first else {
        panic!("first round must request input");
    };
    let request_state = input_required.request_state.expect("request state");
    let requests = input_required.input_requests.expect("input requests");
    let request = requests.get("background").expect("background request");
    let request_value = serde_json::to_value(request).expect("serialize request");
    assert_eq!(
        request_value["params"]["requestedSchema"]["properties"]["background"]["type"],
        "boolean"
    );

    let mut responses = InputResponses::new();
    responses.insert(
        "background".to_string(),
        json!({"action": "accept", "content": {"background": true}}),
    );
    let retry = server
        .modern_open_idb_background_decision(
            path,
            size,
            Some(request_state.clone()),
            Some(responses),
        )
        .expect("valid retry");
    assert!(matches!(retry, OpenIdbBackgroundDecision::Ready(true)));

    assert!(server
        .modern_open_idb_background_decision(
            "/tmp/different-macho",
            size,
            Some(request_state.clone()),
            Some(InputResponses::new()),
        )
        .is_err());
    assert!(server
        .modern_open_idb_background_decision(
            path,
            size,
            Some(format!("{request_state}tampered")),
            Some(InputResponses::new()),
        )
        .is_err());
}

#[test]
fn modern_open_idb_mrtr_decline_keeps_foreground_behavior() {
    let server = test_server();
    let path = "/tmp/large-macho";
    let size = crate::server::OPEN_IDB_AUTO_BACKGROUND_THRESHOLD_BYTES + 1;
    let first = server
        .modern_open_idb_background_decision(path, size, None, None)
        .expect("first MRTR round");
    let OpenIdbBackgroundDecision::InputRequired(input_required) = first else {
        panic!("first round must request input");
    };
    let mut responses = InputResponses::new();
    responses.insert("background".to_string(), json!({"action": "decline"}));
    let retry = server
        .modern_open_idb_background_decision(
            path,
            size,
            input_required.request_state,
            Some(responses),
        )
        .expect("valid decline");

    assert!(matches!(retry, OpenIdbBackgroundDecision::Ready(false)));
}

/// A killed idat leaves partial artifacts that `dsc_open_plan` would
/// otherwise reuse; cancellation cleanup must remove exactly those.
#[test]
fn remove_partial_idat_outputs_deletes_packed_and_unpacked_artifacts() {
    let dir = std::env::temp_dir().join(format!("ida-mcp-partial-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let out_i64 = dir.join("cache.i64");
    let unpacked = dir.join("cache.id0");
    let unrelated = dir.join("keep.txt");
    std::fs::write(&out_i64, b"partial").expect("write i64");
    std::fs::write(&unpacked, b"partial").expect("write id0");
    std::fs::write(&unrelated, b"keep").expect("write unrelated");

    crate::server::remove_partial_idat_outputs(&out_i64);

    assert!(!out_i64.exists(), "packed database must be removed");
    assert!(!unpacked.exists(), "unpacked component must be removed");
    assert!(unrelated.exists(), "unrelated files must be untouched");
    let _ = std::fs::remove_dir_all(&dir);
}

fn create_sparse_test_file(name: &str, len: u64) -> std::io::Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!("ida-mcp-{name}-{}", uuid::Uuid::new_v4()));
    let file = std::fs::File::create(&path)?;
    file.set_len(len)?;
    Ok(path)
}

fn metadata_map(grant: Option<Result<CloseTokenGrant, String>>) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    apply_close_metadata(&mut map, grant, close_hint_for(crate::ServerMode::Http));
    map
}

#[test]
fn close_metadata_grant_emits_token_owner_and_hint() {
    let map = metadata_map(Some(Ok(CloseTokenGrant {
        token: "tok-1".into(),
        reused: false,
        owner_session_id: "session-a".into(),
    })));
    assert_eq!(
        map.get("close_token").and_then(Value::as_str),
        Some("tok-1")
    );
    assert_eq!(
        map.get("close_owner_session_id").and_then(Value::as_str),
        Some("session-a")
    );
    assert!(map.contains_key("close_hint"));
    assert!(!map.contains_key("close_token_reused"));
    assert!(!map.contains_key("close_recovery_hint"));
}

#[test]
fn close_metadata_marks_reused_grant() {
    let map = metadata_map(Some(Ok(CloseTokenGrant {
        token: "tok-2".into(),
        reused: true,
        owner_session_id: "session-a".into(),
    })));
    assert_eq!(
        map.get("close_token_reused").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn close_metadata_denial_emits_owner_recovery_hint_and_no_token() {
    let map = metadata_map(Some(Err("session-original".into())));
    assert!(!map.contains_key("close_token"));
    assert_eq!(
        map.get("close_owner_session_id").and_then(Value::as_str),
        Some("session-original")
    );
    let recovery = map
        .get("close_recovery_hint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(recovery.contains("force=true"));
    let hint = map
        .get("close_hint")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(hint.contains("session-original"));
}

#[test]
fn close_metadata_none_emits_only_hint() {
    let map = metadata_map(None);
    assert!(map.contains_key("close_hint"));
    assert!(!map.contains_key("close_token"));
    assert!(!map.contains_key("close_owner_session_id"));
    assert!(!map.contains_key("close_recovery_hint"));
}

// -----------------------------------------------------------------------
// Composite tool helpers
// -----------------------------------------------------------------------

/// Compiling the category table is lazy and panics on a bad pattern, so
/// this is also the test that proves every pattern in it is valid regex.
#[test]
fn import_categories_bucket_by_first_match() {
    for (name, expected) in [
        ("CryptEncrypt", "crypto"),
        ("SHA256_Update", "crypto"),
        ("getaddrinfo", "network"),
        ("__recv_chk", "network"),
        ("RegOpenKeyExW", "registry"),
        // Decoration must not defeat an anchored pattern.
        ("_RegQueryValueExA", "registry"),
        // `process` before `file_io`: dlopen is not file work.
        ("dlopen", "process"),
        ("pthread_create", "process"),
        ("fopen", "file_io"),
        ("closedir", "file_io"),
        ("malloc", "memory"),
        ("memcpy", "memory"),
        ("strlen", "string"),
        ("__printf_chk", "string"),
        ("localtime_r", "time"),
        ("__libc_start_main", "other"),
    ] {
        assert_eq!(import_category(name), expected, "{name}");
    }
}

#[test]
fn survey_function_kind_prefers_the_most_specific_shape() {
    // Size wins over call count: a 6-byte jump stub is a thunk even when
    // it "calls" something.
    assert_eq!(survey_function_kind(6, 1), "thunk");
    assert_eq!(survey_function_kind(6, 0), "thunk");
    assert_eq!(survey_function_kind(64, 0), "leaf");
    assert_eq!(survey_function_kind(64, 3), "normal");
    assert_eq!(survey_function_kind(64, 8), "hub");
}

#[test]
fn cyclomatic_complexity_matches_the_cfg_formula() {
    assert_eq!(cyclomatic_complexity(2, 1), 1);
    assert_eq!(cyclomatic_complexity(3, 3), 2);
    assert_eq!(cyclomatic_complexity(0, 0), 0);
    assert_eq!(cyclomatic_complexity(0, 4), 0);
}

#[test]
fn compact_component_strings_dedups_and_caps() {
    assert_eq!(
        compact_component_strings(["ok", "", "ok", "next", "third"], 2),
        ["ok", "next"]
    );
}

#[test]
fn component_internal_call_graph_keeps_only_in_component_edges() {
    let graph = component_internal_call_graph(
        &[0x1000, 0x2000],
        &[
            (0x1000, 0x2000, "b"),
            (0x1000, 0x3000, "c"),
            (0x2000, 0x1000, "a"),
        ],
    );
    assert_eq!(
        graph.nodes,
        vec!["0x1000".to_string(), "0x2000".to_string()]
    );
    assert_eq!(
        graph.edges,
        vec![
            crate::server::responses::ComponentCallEdge {
                from: "0x1000".to_string(),
                to: "0x2000".to_string(),
                name: "b".to_string(),
            },
            crate::server::responses::ComponentCallEdge {
                from: "0x2000".to_string(),
                to: "0x1000".to_string(),
                name: "a".to_string(),
            },
        ]
    );
}

#[test]
fn analyze_component_request_accepts_address_and_functions_aliases() {
    let from_addrs: AnalyzeComponentRequest =
        serde_json::from_value(json!({"addrs": ["main"]})).unwrap();
    let from_address: AnalyzeComponentRequest =
        serde_json::from_value(json!({"address": "0x1000"})).unwrap();
    let from_functions: AnalyzeComponentRequest =
        serde_json::from_value(json!({"functions": "main,check_pw"})).unwrap();
    assert_eq!(from_addrs.addrs, Some(json!(["main"])));
    assert_eq!(from_address.addrs, Some(json!("0x1000")));
    assert_eq!(from_functions.addrs, Some(json!("main,check_pw")));
}

#[tokio::test]
async fn analyze_component_rejects_an_empty_list() {
    let server = test_server();
    let result = server
        .analyze_component(Parameters(AnalyzeComponentRequest {
            addrs: Some(json!([])),
            timeout_secs: None,
        }))
        .await
        .expect("handler returns Ok with an error result");
    assert_eq!(result.is_error, Some(true));
    let text = tool_result_text(result);
    assert!(
        text.to_ascii_lowercase().contains("empty"),
        "expected an empty-list diagnostic, got {text:?}"
    );
}

#[tokio::test]
async fn analyze_component_rejects_missing_addrs() {
    let server = test_server();
    let result = server
        .analyze_component(Parameters(AnalyzeComponentRequest {
            addrs: None,
            timeout_secs: None,
        }))
        .await
        .expect("handler returns Ok with an error result");
    assert_eq!(result.is_error, Some(true));
}

#[tokio::test]
async fn analyze_component_rejects_an_unresolvable_name() {
    let server = test_server();
    let result = server
        .analyze_component(Parameters(AnalyzeComponentRequest {
            addrs: Some(json!(["nonexistent_function_name_xyz"])),
            timeout_secs: None,
        }))
        .await
        .expect("handler returns Ok with an error result");
    assert_eq!(result.is_error, Some(true));
    let text = tool_result_text(result);
    assert!(
        text.contains("Cannot resolve address") && text.contains("nonexistent_function_name_xyz"),
        "expected a resolve failure, got {text:?}"
    );
}

#[test]
fn diff_before_after_request_rejects_missing_or_unknown_action() {
    assert!(
        serde_json::from_value::<DiffBeforeAfterRequest>(json!({"address": "0x1000"})).is_err(),
        "missing action must fail to deserialize"
    );
    assert!(
        serde_json::from_value::<DiffBeforeAfterRequest>(json!({
            "address": "0x1000",
            "action": "explode"
        }))
        .is_err(),
        "unknown action must fail to deserialize"
    );
}

#[test]
fn trace_direction_defaults_to_forward_and_max_depth_clamps() {
    assert_eq!(trace_direction_or_default(None), TraceDirection::Forward);
    assert_eq!(
        trace_direction_or_default(Some(TraceDirection::Backward)),
        TraceDirection::Backward
    );
    assert_eq!(clamp_trace_max_depth(None), 5);
    assert_eq!(clamp_trace_max_depth(Some(0)), 1);
    assert_eq!(clamp_trace_max_depth(Some(21)), 20);
    assert_eq!(clamp_trace_max_depth(Some(-3)), 1);
}

#[test]
fn trace_data_flow_step_emits_two_xrefs_and_skips_visited() {
    let xrefs = [
        TraceXrefHop {
            from: 0x1000,
            to: 0x2000,
            is_code: true,
        },
        TraceXrefHop {
            from: 0x1000,
            to: 0x3000,
            is_code: false,
        },
    ];
    let visited = std::collections::HashSet::from([0x1000, 0x2000]);
    let (edges, next) = trace_data_flow_step(0x1000, TraceDirection::Forward, &xrefs, &visited);
    assert_eq!(edges.len(), 2);
    assert_eq!(edges[0].to, 0x2000);
    assert_eq!(edges[1].to, 0x3000);
    assert_eq!(next, vec![0x3000]);
}

#[tokio::test]
async fn func_profile_rejects_empty_targets() {
    let server = test_server();
    let result = server
        .func_profile(Parameters(FuncProfileRequest {
            address: None,
            target_name: None,
            include_lists: None,
            max_items: None,
            timeout_secs: None,
        }))
        .await
        .expect("handler returns Ok with an error result");
    assert_eq!(result.is_error, Some(true));
}

#[test]
fn survey_metric_index_keys_by_parsed_address() {
    let metrics = json!({
        "functions": [
            {"address": "0x1000", "xrefs": 4, "incoming_calls": 2, "outgoing_calls": 7},
            // Unparseable addresses are dropped, not fatal.
            {"address": "not-an-address", "xrefs": 9},
        ],
        "strings": [{"address": "0x2000", "xrefs": 11}],
    });

    let functions = survey_metric_index(Some(&metrics), "functions");
    assert_eq!(functions.len(), 1);
    let metric = functions[&0x1000];
    assert_eq!(
        (metric.xrefs, metric.incoming_calls, metric.outgoing_calls),
        (4, 2, 7)
    );

    let strings = survey_metric_index(Some(&metrics), "strings");
    assert_eq!(strings[&0x2000].xrefs, 11);
    // A skipped metrics pass indexes to nothing rather than failing.
    assert!(survey_metric_index(None, "functions").is_empty());
    assert!(survey_metric_index(Some(&metrics), "absent").is_empty());
}

#[test]
fn meta_string_drops_blank_and_missing_fields() {
    let meta = json!({"md5": "d41d8c", "sha256": "   ", "bits": 64});

    assert_eq!(meta_string(&meta, "md5"), Some("d41d8c".to_string()));
    assert_eq!(meta_string(&meta, "sha256"), None);
    assert_eq!(meta_string(&meta, "bits"), None);
    assert_eq!(meta_string(&meta, "absent"), None);
}

// ---------------------------------------------------------------------
// VibRev slice: one definition per tool, feeding both the MCP surface and the
// derived CLI tree
// ---------------------------------------------------------------------

/// Tools the macro structurally refuses, and why.
///
/// Each takes an argument that exists on an MCP *request* and has no command
/// line equivalent — `RequestContext` for the peer and cancellation token,
/// `RequestState`/`ToolInputResponses` for an elicitation round trip. The
/// macro names the offending parameter at compile time rather than failing
/// as an arity mismatch inside the expansion. They stay on plain
/// `#[rmcp::tool]`, which still carries `title` and `annotations`, so their
/// metadata is declared at the definition site like everything else — only
/// their CLI is missing, and that is a real boundary rather than a gap.
const NOT_DISPATCHABLE: &[&str] = &[
    "analyze_funcs",
    "open_dsc",
    "open_idb",
    "run_script",
    "task_status",
];

/// Tools that could carry `#[vibrev_tool]` and do not yet. Shrinks to empty;
/// never grows.
const NOT_YET_MIGRATED: &[&str] = &[];

/// Every tool that *can* declare its own CLI does, and the two lists of
/// exceptions account for the rest exactly.
///
/// Stated as a subtraction rather than as a roster so that the end state —
/// `NOT_YET_MIGRATED` empty — is the claim the test already makes, instead
/// of something a later reader has to infer from a list of 73 names.
#[test]
fn every_dispatchable_tool_declares_its_own_cli() {
    let all: Vec<String> = IdaMcpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(all.len(), 85, "the tool surface changed size");

    let mut expected: Vec<String> = all
        .iter()
        .filter(|n| {
            !NOT_DISPATCHABLE.contains(&n.as_str()) && !NOT_YET_MIGRATED.contains(&n.as_str())
        })
        .cloned()
        .collect();
    expected.sort();

    let mut derived: Vec<String> = IdaMcpServer::vibrev_tool_defs()
        .iter()
        .map(|d| d.name().to_string())
        .collect();
    derived.sort();
    assert_eq!(derived, expected);

    // Both exception lists must name tools that exist, or a rename would
    // quietly excuse a tool from the migration forever.
    for name in NOT_DISPATCHABLE.iter().chain(NOT_YET_MIGRATED) {
        assert!(all.iter().any(|n| n == name), "{name} is not a tool");
    }
}

/// The tables are dead for the native surface.
///
/// There is one source of a tool's title and annotations — its attribute — and
/// the way to say so is that `set_tool_metadata`, the place the tables are
/// applied, changes nothing about any of the 78. Stated that way rather than as
/// "the tables are short", because a table that is merely unused today is one
/// arm away from being consulted again.
#[test]
fn no_native_tool_gets_its_metadata_from_a_table() {
    for tool in IdaMcpServer::tool_router().list_all() {
        let name = tool.name.to_string();
        let declared_title = tool.title.clone();
        let declared_annotations = tool.annotations.clone();
        assert!(declared_title.is_some(), "{name} declares no title");
        assert!(
            declared_annotations.is_some(),
            "{name} declares no annotations"
        );

        let filled = super::apply_tool_metadata(tool);
        assert_eq!(filled.title, declared_title, "{name}: the table overrode");
        assert_eq!(
            serde_json::to_value(&filled.annotations).expect("annotations serialize"),
            serde_json::to_value(&declared_annotations).expect("annotations serialize"),
            "{name}: the table overrode"
        );

        // …and the tables have nothing to say about it anyway.
        assert_eq!(tool_title_for(&name), None, "{name} is still in the table");
    }
}

/// What is left of the tables is exactly the supervisor's session lifecycle,
/// which is built from hand-written `Tool` structs and has no attribute to
/// declare anything on.
#[test]
fn the_tables_now_serve_only_the_supervisor_session_tools() {
    for name in crate::supervisor::server::SESSION_TOOLS {
        assert!(
            tool_title_for(name).is_some(),
            "{name} lost its title with the tables"
        );
    }
    // The fallback arm does not hand out `read_only` to a name nobody
    // described: an undescribed tool is treated as dangerous, not as safe.
    let unknown =
        serde_json::to_value(tool_annotations_for("not_a_tool")).expect("annotations serialize");
    assert_eq!(unknown["readOnlyHint"], serde_json::json!(false));
    assert_eq!(unknown["destructiveHint"], serde_json::json!(true));
}

/// Every derived tool publishes an `outputSchema`.
///
/// rmcp derives one only from `Json<T>`, and these tools hand-build a
/// `CallToolResult`, so the schema comes from the attribute's `output = "..."` —
/// the one part of a tool's contract that is restated by hand, and therefore the
/// one an edit can drop. `tool_surface`'s `TOOLS_WITH_OUTPUT_SCHEMA` is the
/// roster; this checks it against the derived defs rather than against
/// `tools/list`, so a tool that loses its schema fails here first, next to the
/// attribute that caused it.
#[test]
fn migrating_a_tool_never_drops_its_output_schema() {
    for def in IdaMcpServer::vibrev_tool_defs() {
        let name = def.name();
        assert!(
            def.tool.output_schema.is_some(),
            "{name} lost its output schema"
        );
    }
}

/// The claim the whole slice rests on: one definition, two front ends, no drift.
///
/// `decompile` rejects a malformed address before it reaches the worker, so
/// this runs the *real* tool body — no IDA, no database — down both paths
/// and compares what each front end would show.
#[tokio::test]
async fn both_front_ends_return_the_same_bytes_for_the_same_call() {
    let server = test_server();
    let args = json!({ "address": "not-an-address" });

    // CLI path.
    let outcome = server
        .vibrev_call("decompile", args.clone())
        .await
        .expect("the call itself succeeds; the tool reports the failure");

    // MCP path, through the router the way `tools/call` does.
    let mcp = server
        .decompile(Parameters(
            serde_json::from_value(args).expect("arguments deserialize"),
        ))
        .await
        .expect("the handler returns Ok with an error result");

    let mcp_text = mcp
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|text| text.text.clone())
        .expect("the error result carries text");

    // Two empty strings would compare equal and prove nothing.
    assert!(
        mcp_text.contains("not-an-address"),
        "expected the tool's own diagnostic, got {mcp_text:?}"
    );
    assert_eq!(
        outcome.text, mcp_text,
        "the CLI would print something other than what `content[0]` carries"
    );
    assert_eq!(outcome.structured, mcp.structured_content);
}

/// A tool that ran and failed keeps saying so on both faces.
///
/// This is what `Result<Rendered<T>, ErrorData>` cannot express and why the
/// slice carries `ToolOutcome`: every IDA tool reports failure as
/// `Ok(CallToolResult { is_error: true })`, and `src/ida/remote`'s classifier
/// reads exactly that flag to tell a wedged worker from a bad argument.
#[tokio::test]
async fn a_failing_tool_is_an_error_on_both_faces() {
    let server = test_server();
    let args = json!({ "address": "not-an-address" });

    let outcome = server
        .vibrev_call("decompile", args.clone())
        .await
        .expect("a tool-level failure is not a call-level failure");
    assert!(outcome.is_error, "the CLI would have exited 0 on a failure");

    let mcp = server
        .decompile(Parameters(
            serde_json::from_value(args).expect("arguments deserialize"),
        ))
        .await
        .expect("the handler returns Ok");
    assert_eq!(mcp.is_error, Some(true));

    // And the classifier the supervisor runs on that result still fires.
    assert!(
        crate::ida::remote::result_error(&mcp, "decompile").is_some(),
        "the child-error classifier stopped recognizing this failure"
    );
}

/// An unknown tool is a *call* failure, not a tool failure — the CLI must
/// not report it as a tool that ran and said no.
#[tokio::test]
async fn an_unmigrated_tool_is_not_reachable_from_the_derived_cli() {
    let server = test_server();
    let error = server
        .vibrev_call("open_idb", json!({}))
        .await
        .expect_err("open_idb takes extractors the CLI cannot supply");
    assert!(error.message.contains("unknown tool"), "{}", error.message);
}

/// The name-collision check against the real manifest: it runs over this
/// engine's actual management commands, and the tool tree builds.
#[test]
fn the_derived_tree_builds_against_the_real_management_commands() {
    let cmd = IdaMcpServer::vibrev_cli("ida-headless-mcp")
        .with_management(&["serve", "serve-http", "worker", "probe"])
        .with_session(&super::SESSION)
        .command();
    let mut names: Vec<&str> = cmd
        .find_subcommand(vibrev_kit::cli::TOOL_COMMAND)
        .expect("the tool subtree exists")
        .get_subcommands()
        .map(|c| c.get_name())
        .filter(|n| *n != "help")
        .collect();
    names.sort();

    // Every derived tool except the ones that declared `cli(none)`.
    let mut expected: Vec<String> = IdaMcpServer::vibrev_tool_defs()
        .iter()
        .filter(|d| d.cli.enabled)
        .map(|d| d.name().to_string())
        .collect();
    expected.sort();
    assert_eq!(names, expected);
}

/// …and the check is live rather than vacuously true: IDA's flat tool
/// names happen not to collide with `serve`/`serve-http`/`worker`/`probe`
/// today, so assert it *would* fire, using a real tool name.
#[test]
#[should_panic(expected = "管理命令名 `segments`")]
fn a_management_command_may_not_take_a_real_tool_name() {
    let _ = IdaMcpServer::vibrev_cli("ida-headless-mcp")
        .with_management(&["serve", "segments"])
        .command();
}

/// Every published name, checked against the four this engine registers.
/// This is exactly the risk a flat name space carries — dozens of tool names
/// next to a handful of management commands — so measure it rather than
/// assume it.
#[test]
fn no_published_tool_name_collides_with_a_management_command() {
    let management = ["serve", "serve-http", "worker", "probe", "help", "tool"];
    let colliding: Vec<String> = IdaMcpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .filter(|name| management.contains(&name.as_str()))
        .collect();
    assert!(
        colliding.is_empty(),
        "these tools would shadow a management command if the tree were flat: {colliding:?}"
    );
}
