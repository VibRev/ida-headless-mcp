//! Rename, comment, patch, Lumina, and SDK-mutation output types.
//!
//! Every edit tool answers with what it did, not with a bare acknowledgement:
//! the address it resolved, the value it wrote, and — where the SDK reports one
//! — the status code it got back. `code == 0` means success for the stack-frame
//! operations; a non-zero code arrives as `status: "error"` in a *successful*
//! tool call, so a client must read `status`, not just the absence of
//! `isError`.

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `rename` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameResult {
    /// Address that was renamed, hex-formatted.
    pub address: String,
    /// The new name.
    pub name: String,
    /// IDA `SN_*` flag bits that were applied; 0 for the default naming rules.
    pub flags: i32,
}

/// `set_comments` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCommentsResult {
    /// Address that was commented, hex-formatted.
    pub address: String,
    /// True when the comment was set as repeatable.
    pub repeatable: bool,
    /// The comment text that was written.
    pub comment: String,
}

/// `comment_append` output.
///
/// Exactly one of `appended` and `skipped` is present: `skipped` when
/// `dedupe` was on and the line was already there, `appended` otherwise.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppendCommentResult {
    /// The requested address, hex-formatted.
    pub address: String,
    /// Where the text went: `func` for a function comment, `line` otherwise.
    pub scope: String,
    /// True when the text was appended; absent when it was skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appended: Option<bool>,
    /// True when `dedupe` suppressed a duplicate line; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<bool>,
}

/// `bookmark_add` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookmarkResult {
    /// Address that was marked, hex-formatted.
    pub address: String,
    /// Bookmark slot index; an existing mark on the same address is reused.
    pub slot: u32,
    /// The description that was stored.
    pub description: String,
}

/// `patch` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchResult {
    /// Address the write started at, hex-formatted.
    pub address: String,
    /// Number of bytes written.
    pub length: usize,
}

/// `patch_asm` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchAsmResult {
    /// Address the instruction was assembled at, hex-formatted.
    pub address: String,
    /// The assembly source that was assembled.
    pub line: String,
    /// Number of bytes the instruction encoded to.
    pub length: usize,
    /// The encoded bytes, lowercase hex, space-separated.
    pub bytes: String,
}

/// Shared shape of `lumina_lookup` and `lumina_apply`.
///
/// `applied` is false on a lookup (it never writes) and reports whether the
/// apply actually changed the function. Keys that Lumina left empty arrive
/// as null.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LuminaPullOutput {
    pub address: String,
    pub status: String,
    pub matched_name: Option<String>,
    pub matched_size: Option<u64>,
    pub frequency: Option<u64>,
    pub score: Option<f64>,
    pub metadata_keys: Option<Vec<String>>,
    pub applied: bool,
    pub force: bool,
    pub backup_created: Option<bool>,
    pub previous_name: Option<String>,
    pub current_name: Option<String>,
    pub error: Option<String>,
}

/// One function entry from `sdk_mutation` `survey_metrics`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SdkSurveyFunction {
    pub address: String,
    pub xrefs: usize,
    pub incoming_calls: usize,
    pub outgoing_calls: usize,
}

/// One string entry from `sdk_mutation` `survey_metrics`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SdkSurveyString {
    pub address: String,
    pub xrefs: usize,
}

/// `sdk_mutation` output. Thirteen actions, one object; each action fills
/// a different subset. A single `anyOf` root would be rejected by the
/// supervisor's wrapper heuristic, so the unused keys are simply absent.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SdkMutationOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_created: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_created: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<SdkSurveyFunction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strings: Option<Vec<SdkSurveyString>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operand: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_decl: Option<String>,
}
