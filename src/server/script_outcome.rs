//! Parse the JSON payload returned by `run_script`.

use serde_json::Value;

pub(crate) const RUN_SCRIPT_PREVIEW_CHARS: usize = 220;
pub(crate) const RUN_SCRIPT_TAIL_LINES: usize = 12;
pub(crate) const RUN_SCRIPT_TAIL_CHARS: usize = 1600;

/// One `run_script` result. The worker already shaped the JSON; this type
/// knows how to read success / failure / timeout out of that shape.
pub(crate) struct ScriptOutcome<'a>(&'a Value);

impl<'a> ScriptOutcome<'a> {
    pub(crate) fn new(result: &'a Value) -> Self {
        Self(result)
    }

    pub(crate) fn succeeded(&self) -> bool {
        self.0.get("success").and_then(Value::as_bool) == Some(true)
    }

    fn field(&self, field: &str) -> Option<&str> {
        self.0.get(field).and_then(Value::as_str)
    }

    pub(crate) fn failure_message(&self) -> String {
        let stderr = self.field("stderr").unwrap_or_default();
        let stdout = self.field("stdout").unwrap_or_default();
        let summary = self
            .field("error_summary")
            .or_else(|| self.field("error"))
            .or_else(|| last_non_empty_line(stderr))
            .unwrap_or("Unknown IDAPython script failure (no error details captured)");

        let stderr_tail = truncate_chars(
            &tail_lines(stderr, RUN_SCRIPT_TAIL_LINES),
            RUN_SCRIPT_TAIL_CHARS,
        );
        let stdout_tail = truncate_chars(
            &tail_lines(stdout, RUN_SCRIPT_TAIL_LINES),
            RUN_SCRIPT_TAIL_CHARS,
        );

        let mut parts = vec![format!("IDAPython script execution failed: {summary}")];
        if let Some(kind) = self.field("error_kind") {
            parts.push(format!("Error kind: {kind}"));
        }
        if !stderr_tail.is_empty() {
            parts.push(format!("stderr (tail):\n{stderr_tail}"));
        }
        if !stdout_tail.is_empty() {
            parts.push(format!("stdout (tail):\n{stdout_tail}"));
        }
        let combined_details = format!("{summary}\n{stderr_tail}");
        if let Some(hint) = error_hint(&combined_details) {
            parts.push(format!("Hint: {hint}"));
        }
        parts.join("\n\n")
    }

    pub(crate) fn timeout_message(timeout_secs: u64, code: &str) -> String {
        let compact_preview = code
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let preview = if compact_preview.is_empty() {
            "<empty script>".to_string()
        } else {
            truncate_chars(&compact_preview, RUN_SCRIPT_PREVIEW_CHARS)
        };
        format!(
            "run_script timed out after {timeout_secs} seconds.\n\
             The script may be blocked in a long-running loop or waiting on IDA state.\n\
             Script preview: {preview}\n\
             Hint: while iterating with LLM-generated code, use a smaller timeout_secs and avoid scripts that block indefinitely."
        )
    }
}

pub(crate) fn run_script_succeeded(result: &Value) -> bool {
    ScriptOutcome::new(result).succeeded()
}

pub(crate) fn run_script_failure_message(result: &Value) -> String {
    ScriptOutcome::new(result).failure_message()
}

pub(crate) fn run_script_timeout_message(timeout_secs: u64, code: &str) -> String {
    ScriptOutcome::timeout_message(timeout_secs, code)
}

fn last_non_empty_line(text: &str) -> Option<&str> {
    text.lines().rev().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn tail_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn error_hint(error_details: &str) -> Option<&'static str> {
    let lowered = error_details.to_ascii_lowercase();
    if lowered.contains("syntaxerror") || lowered.contains("invalid syntax") {
        return Some("Python syntax error detected. Regenerate valid Python and retry.");
    }
    if lowered.contains("nameerror") {
        return Some("NameError detected. Check variable/module names before rerunning.");
    }
    if lowered.contains("attributeerror") {
        return Some("AttributeError detected. Verify IDA API object names/methods.");
    }
    if lowered.contains("importerror") || lowered.contains("modulenotfounderror") {
        return Some("Import failure detected. Ensure the required module exists in IDAPython.");
    }
    if lowered.contains("failed to execute wrapper") {
        return Some(
            "IDAPython wrapper execution failed before user code completed. Check stderr for details.",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::truncate_chars;

    #[test]
    fn truncate_chars_appends_ellipsis() {
        assert_eq!(truncate_chars("abcdef", 3), "abc...");
        // A string that fits gets no ellipsis, so a short preview cannot be
        // read as a clipped one.
        assert_eq!(truncate_chars("abc", 10), "abc");
    }
}
