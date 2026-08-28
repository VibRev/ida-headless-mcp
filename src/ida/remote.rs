//! Helpers for calling a child `ida-mcp worker` over MCP stdio.

use crate::error::ToolError;
use rmcp::model::{CallToolRequestParams, CallToolResult, ContentBlock, JsonObject};
use rmcp::service::{Peer, RoleClient};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) fn hex_addr(addr: u64) -> Value {
    Value::String(format!("0x{addr:x}"))
}

pub(crate) fn json_object(value: Value) -> Result<JsonObject, ToolError> {
    match value {
        Value::Object(map) => Ok(map),
        other => Err(ToolError::RemoteProtocol(format!(
            "tool arguments must be a JSON object, got {other:?}"
        ))),
    }
}

pub(crate) fn strip_worker_metadata(value: &mut Value) {
    let Value::Object(map) = value else {
        return;
    };
    for key in [
        "session_id",
        "close_hint",
        "close_owner_session_id",
        "close_token",
        "close_token_reused",
        "close_recovery_hint",
    ] {
        map.remove(key);
    }
}

/// Transport / worker-lifecycle failures. Tool-level `isError` (`IdaError` /
/// `IdaErrorDetail`) is not in this set so the supervisor can forward it.
pub(crate) fn is_lifecycle_error(err: &ToolError) -> bool {
    matches!(
        err,
        ToolError::WorkerClosed
            | ToolError::WorkerCrashed { .. }
            | ToolError::WorkerRetired(_)
            | ToolError::Timeout(_)
            | ToolError::TimeoutDetailed(_)
            | ToolError::Cancelled(_)
    )
}

/// Strip supervisor-private worker metadata from a forwarded `CallToolResult`.
///
/// When `content[0]` is the JSON of `structured_content` (pretty or compact),
/// the same keys are removed and `content[0]` is rewritten as pretty JSON so
/// the two halves cannot drift. Other text (decompile listings, error
/// sentences) is left alone.
pub(crate) fn strip_call_tool_result(mut result: CallToolResult) -> CallToolResult {
    let first_text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone());

    if let Some(mut structured) = result.structured_content.clone() {
        let content_is_this_json = first_text
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .is_some_and(|parsed| parsed == structured);
        strip_worker_metadata(&mut structured);
        if content_is_this_json {
            rewrite_first_text(
                &mut result,
                serde_json::to_string_pretty(&structured)
                    .unwrap_or_else(|_| structured.to_string()),
            );
        }
        result.structured_content = Some(structured);
        return result;
    }

    if let Some(text) = first_text
        && let Ok(mut value) = serde_json::from_str::<Value>(&text)
    {
        let original = value.clone();
        strip_worker_metadata(&mut value);
        if value != original {
            rewrite_first_text(
                &mut result,
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
            );
        }
    }
    result
}

fn rewrite_first_text(result: &mut CallToolResult, text: String) {
    if result
        .content
        .first()
        .and_then(|content| content.as_text())
        .is_some()
    {
        result.content[0] = ContentBlock::text(text);
    }
}

pub(crate) fn result_text(result: &CallToolResult, tool: &str) -> Result<String, ToolError> {
    if result.is_error == Some(true) {
        return Err(ToolError::IdaError(result_error_message(result, tool)));
    }

    let Some(text) = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
    else {
        return Err(ToolError::RemoteProtocol(format!(
            "child tool {tool} returned no text content"
        )));
    };

    if result.content.len() != 1 {
        return Err(ToolError::RemoteProtocol(format!(
            "child tool {tool} returned {} content items; expected 1",
            result.content.len()
        )));
    }

    Ok(text)
}

fn result_error_message(result: &CallToolResult, tool: &str) -> String {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.clone())
        .unwrap_or_else(|| format!("child tool {tool} returned an error"))
}

/// Classify a child `isError: true` result into a [`ToolError`].
///
/// Two stages, and the order matters. First the message decides the *class*:
/// the pool retires a worker on `WorkerClosed`, releases a lease on a timeout
/// and stays quiet on a cancellation, so those three classes must keep coming
/// out of [`classify_child_error`] exactly as they did before.
///
/// Only afterwards, and only for the catch-all class, does a structured
/// payload get carried across. A child tool that failed *and* answered with the
/// object its `outputSchema` describes (the `declare_stack` family) would
/// otherwise arrive at the caller as a bare sentence with IDA's status code
/// stringified into it. Lifecycle errors never carry one, so nothing that the
/// pool branches on can be reshaped by a child payload.
pub(crate) fn result_error(result: &CallToolResult, tool: &str) -> Option<ToolError> {
    if result.is_error != Some(true) {
        return None;
    }

    let classified = classify_child_error(result_error_message(result, tool));
    match (classified, result.structured_content.clone()) {
        (ToolError::IdaError(message), Some(detail)) => Some(ToolError::IdaErrorDetail {
            message,
            detail: Box::new(detail),
        }),
        (classified, _) => Some(classified),
    }
}

fn classify_child_error(message: String) -> ToolError {
    let lowered = message.to_ascii_lowercase();
    // First, and before the timeout and cancellation phrases: a child that
    // jumped out of a signal handler must be retired whatever else its message
    // happens to say.
    if lowered.contains(crate::crash_guard::WORKER_RETIRED_MARKER) {
        return ToolError::WorkerRetired(message);
    }
    if lowered.contains("worker channel closed") {
        return ToolError::WorkerClosed;
    }
    if lowered.contains("timed out after")
        || lowered.contains("operation timed out")
        || lowered.contains("exceeded worker operation timeout")
    {
        return ToolError::TimeoutDetailed(message);
    }
    if lowered.contains("cancelled") || lowered.contains("canceled") {
        return ToolError::Cancelled(message);
    }
    ToolError::IdaError(message)
}

pub(crate) fn parse_json<T: DeserializeOwned>(
    result: CallToolResult,
    tool: &str,
) -> Result<T, ToolError> {
    if let Some(err) = result_error(&result, tool) {
        return Err(err);
    }

    if let Some(mut structured) = result.structured_content.clone() {
        strip_worker_metadata(&mut structured);
        return serde_json::from_value(structured).map_err(|err| {
            ToolError::RemoteProtocol(format!("failed to parse {tool} structured response: {err}"))
        });
    }

    let text = result_text(&result, tool)?;
    let mut value = serde_json::from_str::<Value>(&text).map_err(|err| {
        ToolError::RemoteProtocol(format!("failed to parse {tool} JSON response: {err}"))
    })?;
    strip_worker_metadata(&mut value);
    serde_json::from_value(value)
        .map_err(|err| ToolError::RemoteProtocol(format!("invalid {tool} response: {err}")))
}

pub(crate) async fn call_tool(
    peer: &Peer<RoleClient>,
    tool: &'static str,
    args: JsonObject,
) -> Result<CallToolResult, ToolError> {
    peer.call_tool(CallToolRequestParams::new(tool).with_arguments(args))
        .await
        .map_err(|err| ToolError::RemoteProtocol(format!("{tool} call failed: {err}")))
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::remote::{parse_json, result_error};
    use rmcp::model::{CallToolResult, ContentBlock as Content};
    use serde_json::{json, Value};

    #[test]
    fn a_structured_error_result_is_an_error() {
        let result = CallToolResult::structured_error(json!({ "message": "bad idb" }));

        let err = result_error(&result, "open_idb").expect("structured error must be classified");

        assert!(
            matches!(&err, ToolError::IdaErrorDetail { message, .. } if message.contains("bad idb")),
            "{err}"
        );
    }

    #[test]
    fn a_failed_operation_carries_the_child_payload() {
        let payload = json!({
            "function": "0x2000",
            "name": "y",
            "offset": -8i64,
            "code": -5,
            "status": "error",
        });
        let mut result = CallToolResult::structured_error(payload.clone());
        result.content = vec![Content::text(
            "declare_stack could not define the stack variable: IDA returned code -5",
        )];

        let err =
            result_error(&result, "declare_stack").expect("failed operation must be classified");

        let ToolError::IdaErrorDetail { message, detail } = &err else {
            panic!("expected a detail-carrying error, got {err}");
        };
        assert!(message.contains("code -5"), "{message}");
        assert_eq!(**detail, payload);
        // The caller-facing result keeps both halves.
        let tool_result = err.to_tool_result();
        assert_eq!(tool_result.is_error, Some(true));
        assert_eq!(tool_result.structured_content, Some(payload));
    }

    #[test]
    fn a_structured_payload_cannot_reshape_a_lifecycle_error() {
        // The pool retires a worker on WorkerClosed and releases a lease on a
        // timeout. A child that attached structured content to one of those
        // must not knock it out of its class.
        for (text, expected) in [
            ("Worker channel closed", "closed"),
            ("open_idb timed out after 600 seconds", "timeout"),
            ("run_script was cancelled by the client", "cancelled"),
        ] {
            let mut result = CallToolResult::structured_error(json!({ "code": -5 }));
            result.content = vec![Content::text(text)];

            let err =
                result_error(&result, "open_idb").expect("lifecycle error must be classified");

            let actual = match err {
                ToolError::WorkerClosed => "closed",
                ToolError::TimeoutDetailed(_) => "timeout",
                ToolError::Cancelled(_) => "cancelled",
                other => panic!("{text:?} was reclassified as {other}"),
            };
            assert_eq!(actual, expected, "{text}");
        }
    }

    #[test]
    fn a_child_worker_closed_error_survives_the_trip() {
        let result = CallToolResult::error(vec![Content::text("Worker channel closed")]);

        let err = result_error(&result, "close_idb").expect("worker closed must be classified");

        assert!(matches!(err, ToolError::WorkerClosed));
    }

    /// The child's own account of a caught SIGSEGV has to survive being
    /// flattened to `isError` + a sentence, because retiring the worker on the
    /// parent's side is what stops the next call reaching the same process.
    #[test]
    fn a_caught_signal_retires_the_worker_that_reported_it() {
        let reported = crate::crash_guard::retired_error(11);
        let result = reported.to_tool_result();

        let err = result_error(&result, "decompile").expect("a retirement must be classified");

        assert!(matches!(err, ToolError::WorkerRetired(_)), "{err}");
        // Lifecycle, not tool-level: the supervisor drops the session instead
        // of forwarding this as an answer the database could give again.
        assert!(crate::ida::remote::is_lifecycle_error(&err));
    }

    #[test]
    fn a_retirement_outranks_the_other_phrases_in_its_message() {
        // The sentence tells the caller to open the database again, and an
        // operation that was cancelled *by* the crash can say so. Neither may
        // demote a retirement to a routine cancellation, which would leave the
        // worker leasable.
        let result = CallToolResult::error(vec![Content::text(format!(
            "run_script was cancelled; {}: signal 11",
            crate::crash_guard::WORKER_RETIRED_MARKER
        ))]);

        let err = result_error(&result, "run_script").expect("a retirement must be classified");

        assert!(matches!(err, ToolError::WorkerRetired(_)), "{err}");
    }

    #[test]
    fn a_child_timeout_survives_the_trip() {
        let result =
            CallToolResult::error(vec![Content::text("open_idb timed out after 600 seconds")]);

        let err = result_error(&result, "open_idb").expect("timeout must be classified");

        assert!(
            matches!(err, ToolError::TimeoutDetailed(message) if message.contains("600 seconds"))
        );
    }

    #[test]
    fn a_child_cancellation_survives_the_trip() {
        let result = CallToolResult::error(vec![Content::text(
            "run_script was cancelled by the client",
        )]);

        let err = result_error(&result, "run_script").expect("cancellation must be classified");

        assert!(matches!(err, ToolError::Cancelled(message) if message.contains("cancelled")));
    }

    #[test]
    fn tool_level_is_error_is_not_lifecycle() {
        let result = CallToolResult::error(vec![Content::text("function not found")]);
        let err =
            crate::ida::remote::result_error(&result, "decompile").expect("tool-level isError");
        assert!(!crate::ida::remote::is_lifecycle_error(&err));
    }

    #[test]
    fn timeout_is_error_is_lifecycle() {
        let result =
            CallToolResult::error(vec![Content::text("open_idb timed out after 600 seconds")]);
        let err = crate::ida::remote::result_error(&result, "open_idb").expect("timeout");
        assert!(crate::ida::remote::is_lifecycle_error(&err));
    }

    #[test]
    fn strip_rewrites_pretty_content_when_it_is_the_structured_object() {
        let structured = json!({
            "addr": "0x1",
            "session_id": "sess-1",
            "close_token": "secret",
        });
        let pretty = serde_json::to_string_pretty(&structured).expect("pretty");
        let mut result = CallToolResult::success(vec![Content::text(pretty)]);
        result.structured_content = Some(structured);

        let stripped = crate::ida::remote::strip_call_tool_result(result);
        let expected = json!({"addr": "0x1"});
        assert_eq!(stripped.structured_content.as_ref(), Some(&expected));
        assert_eq!(
            stripped.content[0].as_text().map(|text| text.text.as_str()),
            Some(
                serde_json::to_string_pretty(&expected)
                    .expect("pretty")
                    .as_str()
            )
        );
    }

    #[test]
    fn strip_leaves_non_json_content_alone() {
        let listing = "int main(void) {\n  return 0;\n}";
        let mut structured = json!({
            "addr": "0x401000",
            "code": listing,
            "session_id": "sess-1",
        });
        let mut result = CallToolResult::success(vec![Content::text(listing)]);
        result.structured_content = Some(structured.clone());

        let stripped = crate::ida::remote::strip_call_tool_result(result);
        crate::ida::remote::strip_worker_metadata(&mut structured);
        assert_eq!(stripped.structured_content.as_ref(), Some(&structured));
        assert_eq!(
            stripped.content[0].as_text().map(|text| text.text.as_str()),
            Some(listing)
        );
    }

    #[test]
    fn parse_json_rejects_structured_error_results() {
        let mut result = CallToolResult::structured_error(json!({ "path": "/tmp/example.i64" }));
        result.content = vec![Content::text("child failed")];

        let err = parse_json::<Value>(result, "open_idb").expect_err("structured error must fail");

        assert!(
            matches!(&err, ToolError::IdaErrorDetail { message, .. } if message == "child failed"),
            "{err}"
        );
    }
}
