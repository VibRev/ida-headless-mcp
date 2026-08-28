//! MCP tool request types.
//!
//! These structs define the parameters for each MCP tool exposed by the server.

use super::address::{value_to_strings, AddressArg};
use super::parse::{page_bounds, parse_optional_unsigned};
use crate::error::ToolError;
use crate::ida::handlers::signature::SignatureRequest;
use crate::ida::query::{
    DscDepsQuery, DscImageQuery, DscStringScope, DscStringSearch, DscSymbolSearch, FunctionQuery,
    FunctionSort, NameQuery, NameSort, StringQuery, StringSearch, StringSort, TypeKind, TypeQuery,
    TypeSort, XrefKind,
};
use crate::ida::scan::{InsnScanRequest, ScanScope, ScopeSpec, DEFAULT_MAX_SCAN};
use crate::ida::signature::SignatureFormat;
use rmcp::schemars::JsonSchema;
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Prose enums
// ---------------------------------------------------------------------------
//
// Five parameters are enums in every sense, and the schema has to say so. As
// plain `Option<String>` with the permitted values written only in English in
// the description, an MCP client gets no validation, the derived CLI gets a
// free-form flag, and `search(kind = "nonsence")` searches for something else
// entirely without saying so.
//
// Declaring them as Rust enums fixes both surfaces at once — schemars publishes
// `enum: [..]`, so MCP clients see the permitted values and the kit gives the
// flag a `PossibleValuesParser`. What it must *not* do is narrow what the MCP
// surface accepts: three of the five take aliases (`immediate`, `quick`, `cfg`,
// …) and all five lower-case and trim their input before matching. A bare
// `#[derive(Deserialize)]` rejects every one of those, which is a contract loss
// in the other direction.
//
// So the variants carry the aliases and [`lenient_enum`] does the
// normalization. schemars reads the variant names and not the aliases, so the
// schema advertises exactly the canonical spellings while the tolerant ones keep
// working.

/// Normalize the tolerant spellings, then decode.
///
/// Trim, lower-case, and fold `-`/space to `_` (the same normalization
/// `ToolCategory::from_str` applies); an empty string reads as "not given",
/// which `survey_binary` treats as `standard`. Anything left over is reported
/// with the permitted values, because the point of declaring these as enums is
/// that a wrong value stops being silent.
fn lenient_enum<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned + JsonSchema,
{
    let Some(raw) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let normalized = raw.trim().to_lowercase().replace(['-', ' '], "_");
    if normalized.is_empty() {
        return Ok(None);
    }
    T::deserialize(
        IntoDeserializer::<serde::de::value::Error>::into_deserializer(normalized.as_str()),
    )
    .map(Some)
    .map_err(|_| {
        serde::de::Error::custom(format!(
            "{raw:?} is not a valid {}; expected one of {}",
            T::schema_name(),
            permitted::<T>().join(", ")
        ))
    })
}

/// The canonical spellings, read back out of the type's own schema so the error
/// message cannot drift from what the schema publishes.
fn permitted<T: JsonSchema>() -> Vec<String> {
    let schema = rmcp::schemars::schema_for!(T);
    schema
        .get("enum")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Where `comment_append` puts the text: on the function, on the instruction, or
/// whichever fits the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommentScope {
    /// Function comment when the address is a function's entry, line otherwise.
    Auto,
    /// Always the function comment.
    Func,
    /// Always the instruction comment.
    Line,
}

impl CommentScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Func => "func",
            Self::Line => "line",
        }
    }
}

/// How much of `survey_binary`'s per-function metrics pass to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SurveyDetail {
    #[serde(alias = "full")]
    Standard,
    #[serde(alias = "quick")]
    Minimal,
}

/// What `search` is looking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SearchKind {
    /// Decide per target: an address-shaped one is an immediate, else text.
    Auto,
    #[serde(alias = "string")]
    Text,
    #[serde(alias = "immediate")]
    Imm,
}

/// `export_funcs` serializations. Only one exists; declaring it is what makes
/// the schema say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
}

/// `tool_catalog`'s category filter. Mirrors `catalog::ToolCategory`, with the
/// aliases its `FromStr` accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogCategory {
    Core,
    #[serde(alias = "function")]
    Functions,
    #[serde(alias = "disasm")]
    Disassembly,
    #[serde(alias = "decompiler")]
    Decompile,
    #[serde(alias = "xref", alias = "references")]
    Xrefs,
    #[serde(alias = "controlflow", alias = "cfg")]
    ControlFlow,
    #[serde(alias = "data")]
    Memory,
    Search,
    #[serde(alias = "meta", alias = "info")]
    Metadata,
    #[serde(alias = "type", alias = "structs")]
    Types,
    #[serde(alias = "edit")]
    Editing,
    #[serde(alias = "script", alias = "python")]
    Scripting,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenIdbRequest {
    #[schemars(description = "Path to .i64/.idb or raw binary.")]
    pub path: String,
    #[schemars(description = "Load external debug info (dSYM/DWARF) after open.")]
    #[serde(alias = "load_dsym")]
    pub load_debug_info: Option<bool>,
    #[schemars(
        description = "Debug info path; defaults to sibling .dSYM. Empty strings are ignored."
    )]
    #[serde(alias = "dsym_path")]
    pub debug_info_path: Option<String>,
    #[schemars(description = "Verbose debug-info loading.")]
    pub debug_info_verbose: Option<bool>,
    #[schemars(description = "Clean up stale lock files from crashed sessions before opening.")]
    #[serde(alias = "recover")]
    pub force: Option<bool>,
    #[schemars(
        description = "For raw binaries, rebuild and overwrite the generated <path>.i64 instead of reusing it. Use when the input binary changed or stale analysis must be replaced."
    )]
    pub rebuild: Option<bool>,
    #[schemars(
        description = "IDA file-type selector (-T). Raw binaries only. Empty strings are ignored."
    )]
    pub file_type: Option<String>,
    #[schemars(
        description = "Run full auto-analysis before returning (default: false). \
        For raw binaries, false returns fast with analysis incomplete; .i64/.idb ignore this. \
        Inputs >50 MiB may route to a background task (response includes analysis_task_id)."
    )]
    pub auto_analyse: Option<bool>,
    #[schemars(description = "Open timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_extra_args")]
    #[schemars(skip)]
    pub worker_extra_args: Vec<String>,
    #[serde(default, rename = "_worker_idb_out")]
    #[schemars(skip)]
    pub worker_idb_out: Option<String>,
}

impl OpenIdbRequest {
    pub fn normalized_debug_info_path(&self) -> Option<String> {
        crate::non_empty_trimmed(self.debug_info_path.as_deref()).map(str::to_string)
    }

    pub fn normalized_file_type(&self) -> Option<String> {
        crate::non_empty_trimmed(self.file_type.as_deref()).map(str::to_string)
    }
}

/// Schema for the elicitation prompt used by `open_idb` when the input binary
/// exceeds the auto-background threshold.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct OpenIdbBackgroundChoice {
    #[schemars(
        description = "Run auto-analysis as a background task with no timeout. \
        Choose 'no' to run inline (capped by the foreground timeout)."
    )]
    pub background: Option<bool>,
}

rmcp::elicit_safe!(OpenIdbBackgroundChoice);

#[cfg(test)]
mod tests {
    use crate::server::requests::OpenIdbRequest;

    fn open_request(debug_info_path: Option<&str>, file_type: Option<&str>) -> OpenIdbRequest {
        OpenIdbRequest {
            path: "/tmp/sample".to_string(),
            load_debug_info: None,
            debug_info_path: debug_info_path.map(str::to_string),
            debug_info_verbose: None,
            force: None,
            rebuild: None,
            file_type: file_type.map(str::to_string),
            auto_analyse: None,
            timeout_secs: None,
            worker_extra_args: Vec::new(),
            worker_idb_out: None,
        }
    }

    #[test]
    fn open_idb_empty_optional_strings_are_ignored() {
        let req = open_request(Some(" \t "), Some(""));
        assert_eq!(req.normalized_debug_info_path(), None);
        assert_eq!(req.normalized_file_type(), None);
    }

    #[test]
    fn open_idb_optional_strings_are_trimmed() {
        let req = open_request(Some(" C:\\symbols\\sample.pdb "), Some(" pe "));
        assert_eq!(
            req.normalized_debug_info_path(),
            Some("C:\\symbols\\sample.pdb".to_string())
        );
        assert_eq!(req.normalized_file_type(), Some("pe".to_string()));
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloseIdbRequest {
    #[schemars(description = "Save database changes before closing (default: true).")]
    pub save: Option<bool>,
    #[schemars(
        description = "Ownership token returned by open_idb. Required when an HTTP/SSE request is not in the owning legacy session; sessionless MCP 2026 clients should provide it unless force=true is used for trusted recovery."
    )]
    #[serde(alias = "close_token", alias = "owner_token")]
    pub token: Option<String>,
    #[schemars(
        description = "Force-close the database when the original HTTP close token was lost. Use only from a trusted client for recovery."
    )]
    #[serde(alias = "recover", alias = "override_owner")]
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoadDebugInfoRequest {
    #[schemars(
        description = "Path to debug info file (e.g., dSYM DWARF). If omitted, tries sibling .dSYM for the current database."
    )]
    pub path: Option<String>,
    #[schemars(description = "Whether to emit verbose load status (default: false)")]
    pub verbose: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EmptyParams {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum functions to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return functions containing this text")]
    #[serde(alias = "query", alias = "queries", alias = "filter")]
    pub filter: Option<String>,
    #[schemars(
        description = "Filter names by regular expression instead of substring. Mutually \
                       exclusive with 'filter'."
    )]
    #[serde(alias = "name_regex")]
    pub regex: Option<String>,
    #[schemars(description = "Only return functions of at least this many bytes")]
    #[schemars(range(min = 0))]
    pub min_size: Option<i64>,
    #[schemars(description = "Only return functions of at most this many bytes")]
    #[schemars(range(min = 0))]
    pub max_size: Option<i64>,
    #[schemars(
        description = "Order the answer by 'address', 'name', or 'size'. Sorting reads every \
                       match before paging, so it costs a full walk of the listing."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub sort_by: Option<FunctionSort>,
    #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
    pub descending: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl ListFunctionsRequest {
    /// Resolve into the worker-side query, clamping the page to the same
    /// ceiling the tool has always published.
    pub fn resolve_query(&self) -> Result<FunctionQuery, ToolError> {
        if self.descending.unwrap_or(false) && self.sort_by.is_none() {
            return Err(ToolError::InvalidParams(
                "'descending' needs a 'sort_by' to reverse".to_string(),
            ));
        }

        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(FunctionQuery {
            offset,
            limit,
            filter: self.filter.clone(),
            regex: self.regex.clone(),
            min_size: parse_optional_unsigned::<usize>(self.min_size, "min_size")?,
            max_size: parse_optional_unsigned::<usize>(self.max_size, "max_size")?,
            sort_by: self.sort_by,
            descending: self.descending.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFuncsRequest {
    #[schemars(
        description = "Return a task_id immediately and run analysis in the background. \
        Use for large binaries (kernelcache, full DSC) that exceed the request timeout."
    )]
    pub background: Option<bool>,
    #[schemars(
        description = "Foreground timeout in seconds (default 120, max 600). Ignored if background=true."
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_no_timeout")]
    #[schemars(skip)]
    pub worker_no_timeout: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveFunctionRequest {
    #[schemars(description = "Function name to resolve (exact or partial match)")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddrInfoRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionAtRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmFunctionAtRequest {
    #[schemars(description = "Address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Number of instructions (1-5000, default: 200)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmRequest {
    #[schemars(description = "Address(es) to disassemble (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisasmByNameRequest {
    #[schemars(description = "Function name to disassemble (exact or partial match)")]
    pub name: String,
    #[schemars(description = "Number of instructions (1-1000, default: 10)")]
    #[schemars(range(min = 1, max = 5000))]
    pub count: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DecompileRequest {
    #[schemars(description = "Address(es) of function to decompile (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StringsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return strings containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(
        description = "Filter string contents by regular expression instead of substring. \
                       Mutually exclusive with 'filter'."
    )]
    pub regex: Option<String>,
    #[schemars(description = "Only return strings of at least this many characters")]
    #[schemars(range(min = 0))]
    pub min_length: Option<i64>,
    #[schemars(description = "Only return strings of at most this many characters")]
    #[schemars(range(min = 0))]
    pub max_length: Option<i64>,
    #[schemars(
        description = "Order the answer by 'address', 'length', or 'content'. Sorting reads \
                       every match before paging, so it costs a full walk of the listing."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub sort_by: Option<StringSort>,
    #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
    pub descending: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl StringsRequest {
    /// Resolve into the worker-side query.
    pub fn resolve_query(&self) -> Result<StringQuery, ToolError> {
        if self.descending.unwrap_or(false) && self.sort_by.is_none() {
            return Err(ToolError::InvalidParams(
                "'descending' needs a 'sort_by' to reverse".to_string(),
            ));
        }

        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(StringQuery {
            offset,
            limit,
            filter: self.filter.clone(),
            regex: self.regex.clone(),
            min_length: parse_optional_unsigned::<usize>(self.min_length, "min_length")?,
            max_length: parse_optional_unsigned::<usize>(self.max_length, "max_length")?,
            sort_by: self.sort_by,
            descending: self.descending.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindStringRequest {
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(
        description = "Treat the query as a regular expression instead of a substring. \
                       Mutually exclusive with 'exact'."
    )]
    pub regex: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl FindStringRequest {
    /// Resolve into the worker-side search.
    ///
    /// The bounds are the hand-written form the two string lookups have always
    /// used, not `page_bounds`: that one clamps `limit` up into `1..=max`, so
    /// adopting it here would change what `limit: 0` answers. Worth doing,
    /// separately.
    pub fn resolve_search(&self) -> Result<StringSearch, ToolError> {
        let limit = parse_optional_unsigned::<usize>(self.limit, "limit")?
            .unwrap_or(100)
            .min(10_000);
        let offset = parse_optional_unsigned::<usize>(self.offset, "offset")?.unwrap_or(0);
        Ok(StringSearch {
            query: self.query.clone(),
            exact: self.exact.unwrap_or(false),
            case_insensitive: self.case_insensitive.unwrap_or(true),
            regex: self.regex.unwrap_or(false),
            offset,
            limit,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsToStringRequest {
    #[schemars(description = "String to search for")]
    pub query: String,
    #[schemars(description = "Exact match (default: false)")]
    pub exact: Option<bool>,
    #[schemars(description = "Case-insensitive match (default: true)")]
    pub case_insensitive: Option<bool>,
    #[schemars(
        description = "Treat the query as a regular expression instead of a substring. \
                       Mutually exclusive with 'exact'."
    )]
    pub regex: Option<bool>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Maximum xrefs per string (default: 64, max: 1024)")]
    #[schemars(range(min = 1, max = 1024))]
    pub max_xrefs: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl XrefsToStringRequest {
    /// Resolve into the worker-side search. `max_xrefs` is not part of it: it
    /// caps what this tool renders per hit, not which strings are hits.
    pub fn resolve_search(&self) -> Result<StringSearch, ToolError> {
        let limit = parse_optional_unsigned::<usize>(self.limit, "limit")?
            .unwrap_or(100)
            .min(10_000);
        let offset = parse_optional_unsigned::<usize>(self.offset, "offset")?.unwrap_or(0);
        Ok(StringSearch {
            query: self.query.clone(),
            exact: self.exact.unwrap_or(false),
            case_insensitive: self.case_insensitive.unwrap_or(true),
            regex: self.regex.unwrap_or(false),
            offset,
            limit,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LocalTypesRequest {
    #[schemars(
        description = "Offset for pagination (default: 0). Positional within the filtered                        listing, not an ordinal: auto-analysis appends types, so a page taken                        while analysis runs can shift. Re-list from 0, or filter by name."
    )]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum types to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return types containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(
        description = "Filter names by regular expression instead of substring. Mutually \
                       exclusive with 'filter'."
    )]
    #[serde(alias = "name_regex")]
    pub regex: Option<String>,
    #[schemars(
        description = "Keep only one kind: 'struct', 'union', 'enum', 'function', 'pointer', \
                       'array', 'typedef', 'other', or 'udt' (struct or union)."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub kind: Option<TypeKind>,
    #[schemars(
        description = "Order the answer by 'ordinal' or 'name'. Sorting reads every match \
                       before paging, so it costs a full walk of the listing."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub sort_by: Option<TypeSort>,
    #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
    pub descending: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl LocalTypesRequest {
    /// Resolve into the worker-side query.
    pub fn resolve_query(&self) -> Result<TypeQuery, ToolError> {
        if self.descending.unwrap_or(false) && self.sort_by.is_none() {
            return Err(ToolError::InvalidParams(
                "'descending' needs a 'sort_by' to reverse".to_string(),
            ));
        }
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(TypeQuery {
            offset,
            limit,
            filter: self.filter.clone(),
            regex: self.regex.clone(),
            kind: self.kind,
            sort_by: self.sort_by,
            descending: self.descending.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeclareTypeRequest {
    #[schemars(description = "C declaration(s) to add to the local type library")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing (allow unknown namespaces)")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Replace existing type if it already exists")]
    pub replace: Option<bool>,
    #[schemars(description = "Parse multiple declarations in one input string")]
    pub multi: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructsRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum structs to return (1-10000, default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Optional filter - only return structs containing this text")]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(
        description = "Filter names by regular expression instead of substring. Mutually \
                       exclusive with 'filter'."
    )]
    #[serde(alias = "name_regex")]
    pub regex: Option<String>,
    #[schemars(description = "Keep only 'struct' or only 'union' (default: both)")]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub kind: Option<TypeKind>,
    #[schemars(
        description = "Order the answer by 'ordinal' or 'name'. Sorting reads every match \
                       before paging, so it costs a full walk of the listing."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub sort_by: Option<TypeSort>,
    #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
    pub descending: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl StructsRequest {
    /// Resolve into the worker-side query.
    pub fn resolve_query(&self) -> Result<TypeQuery, ToolError> {
        if self.descending.unwrap_or(false) && self.sort_by.is_none() {
            return Err(ToolError::InvalidParams(
                "'descending' needs a 'sort_by' to reverse".to_string(),
            ));
        }
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(TypeQuery {
            offset,
            limit,
            filter: self.filter.clone(),
            regex: self.regex.clone(),
            kind: self.kind,
            sort_by: self.sort_by,
            descending: self.descending.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StructInfoRequest {
    #[schemars(
        description = "Local-type-library ordinal, as returned by structs/local_types. Not a                        position in any listing, and mutually exclusive with name — passing both                        is rejected rather than silently resolved."
    )]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
    #[schemars(
        description = "Struct name; exact match first, then a unique case-insensitive substring.                        Prefer this over ordinal."
    )]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadStructRequest {
    #[schemars(description = "Address of struct instance (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(
        description = "Local-type-library ordinal, as returned by structs/local_types. Not a                        position in any listing, and mutually exclusive with name — passing both                        is rejected rather than silently resolved."
    )]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
    #[schemars(
        description = "Struct name; exact match first, then a unique case-insensitive substring.                        Prefer this over ordinal."
    )]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApplyTypesRequest {
    #[schemars(description = "Address to apply type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Stack variable offset (negative for locals)")]
    pub stack_offset: Option<i64>,
    #[schemars(description = "Stack variable name (when applying to stack var)")]
    pub stack_name: Option<String>,
    #[schemars(description = "Named type to apply")]
    pub type_name: Option<String>,
    #[schemars(description = "C declaration to parse and apply")]
    pub decl: Option<String>,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
    #[schemars(description = "Delay function creation if missing")]
    pub delay: Option<bool>,
    #[schemars(description = "Strict application (no type conversion)")]
    pub strict: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InferTypesRequest {
    #[schemars(description = "Address to infer type (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeclareStackRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: i64,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
    #[schemars(description = "C declaration for the variable type")]
    pub decl: String,
    #[schemars(description = "Relaxed parsing for decl")]
    pub relaxed: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteStackRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name")]
    pub target_name: Option<String>,
    #[schemars(description = "Stack offset in bytes (negative for locals, positive for args)")]
    pub offset: Option<i64>,
    #[schemars(description = "Stack variable name (optional)")]
    pub var_name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsToFieldRequest {
    #[schemars(
        description = "Local-type-library ordinal, as returned by structs/local_types. Not a                        position in any listing, and mutually exclusive with name — passing both                        is rejected rather than silently resolved."
    )]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub ordinal: Option<i64>,
    #[schemars(
        description = "Struct name; exact match first, then a unique case-insensitive substring.                        Prefer this over ordinal."
    )]
    #[serde(alias = "struct_name", alias = "type_name")]
    pub name: Option<String>,
    #[schemars(description = "Struct member index (0-based)")]
    #[schemars(range(min = 0, max = 4294967295_i64))]
    pub member_index: Option<i64>,
    #[schemars(description = "Struct member name (exact match)")]
    #[serde(alias = "member", alias = "field", alias = "field_name")]
    pub member_name: Option<String>,
    #[schemars(description = "Maximum xrefs to return (default: 1000, max: 10000)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddressRequest {
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LuminaLookupRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added before resolving the containing function (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Timeout in seconds (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LuminaApplyRequest {
    #[schemars(description = "Function address (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function name (alternative to address)")]
    #[serde(alias = "function", alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added before resolving the containing function (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(
        description = "Force all returned metadata, potentially replacing existing names or types (default: false)"
    )]
    pub force: Option<bool>,
    #[schemars(
        description = "Timeout in seconds. Pooled mode kills and retires the child on timeout; single-worker mode waits for this non-cancellable mutation to finish."
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefsRequest {
    #[schemars(description = "Address(es) (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(description = "Maximum xrefs to return per address (1-10000, default: 1000)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 1, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(
        description = "Keep only 'code' references (calls and jumps), only 'data' references                        (reads and writes), or 'any' (default)."
    )]
    #[serde(default, alias = "xref_type", deserialize_with = "lenient_enum")]
    pub kind: Option<XrefKind>,
    #[schemars(
        description = "Collapse references repeating the same from/to/type triple                        (default: false)"
    )]
    pub dedup: Option<bool>,
    #[schemars(
        description = "Attach the function enclosing each referencing address (default: false)"
    )]
    #[serde(alias = "include_fn")]
    pub include_function: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetBytesRequest {
    #[schemars(description = "Address(es) to read from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to read from (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Number of bytes to read (1-65536, default: 256)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 1, max = 65536))]
    pub size: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetCommentsRequest {
    #[schemars(description = "Address to comment (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to comment (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Comment text (empty string clears comment)")]
    #[serde(alias = "text", alias = "comment")]
    pub comment: String,
    #[schemars(description = "Repeatable comment (default: false)")]
    #[serde(alias = "rptble", alias = "repeatable")]
    pub repeatable: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddBookmarkRequest {
    #[schemars(description = "Address to bookmark (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: AddressArg,
    #[schemars(description = "Bookmark description")]
    #[serde(alias = "name", alias = "title")]
    pub description: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SdkMutationRequest {
    pub action: String,
    pub path: Option<String>,
    pub start: Option<AddressArg>,
    pub end: Option<AddressArg>,
    pub address: Option<AddressArg>,
    // i64 + range instead of u64: schemars renders unsigned integers with a
    // `uint64` format that OpenAPI-3-flavored validators reject.
    #[schemars(range(min = 0))]
    pub size: Option<i64>,
    pub enum_name: Option<String>,
    pub member_name: Option<String>,
    pub value: Option<Value>,
    pub bitfield: Option<bool>,
    pub function_address: Option<AddressArg>,
    pub old_name: Option<String>,
    pub new_name: Option<String>,
    pub stack: Option<bool>,
    pub function_addresses: Option<Vec<AddressArg>>,
    pub string_addresses: Option<Vec<AddressArg>>,
    pub wildcard_operands: Option<bool>,
    pub operand: Option<i32>,
    pub kind: Option<String>,
    pub target: Option<AddressArg>,
    pub struct_name: Option<String>,
    pub delta: Option<i64>,
    pub declaration: Option<String>,
    pub name: Option<String>,
    pub delete_existing: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AppendCommentRequest {
    #[schemars(description = "Address to comment (string/number)")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: AddressArg,
    #[schemars(description = "Comment text to append")]
    pub comment: String,
    #[schemars(description = "Comment scope: auto (default), func, or line")]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub scope: Option<CommentScope>,
    #[schemars(description = "Skip an exact duplicate comment line")]
    pub dedupe: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameRequest {
    #[schemars(description = "Address to rename (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Current name to resolve (alternative to address)")]
    #[serde(alias = "current", alias = "old_name", alias = "from")]
    pub current_name: Option<String>,
    #[schemars(description = "New name for the symbol")]
    #[serde(alias = "new_name", alias = "name")]
    pub name: String,
    #[schemars(description = "IDA set_name flags (optional)")]
    pub flags: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchRequest {
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(
        description = "Bytes to patch (hex string like '90 90' or array of ints/hex strings)"
    )]
    #[serde(alias = "data", alias = "bytes")]
    pub bytes: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PatchAsmRequest {
    #[schemars(description = "Address to patch (string/number)")]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to patch (alternative to address)")]
    #[serde(alias = "name", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to resolved name address (default: 0)")]
    pub offset: Option<i64>,
    #[schemars(description = "Assembly text to assemble and patch")]
    #[serde(alias = "asm", alias = "instruction")]
    pub line: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaginatedRequest {
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum items to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

/// Shared shape of the three symbol listings.
macro_rules! symbol_list_request {
    ($name:ident, $subject:literal $(, $module:ident)?) => {
        #[derive(Debug, Deserialize, JsonSchema)]
        pub struct $name {
            #[schemars(description = "Offset for pagination (default: 0)")]
            #[schemars(range(min = 0))]
            pub offset: Option<i64>,
            #[doc = concat!("Maximum ", $subject, " to return")]
            #[schemars(description = "Maximum entries to return (1-10000, default: 100)")]
            #[serde(alias = "count")]
            #[schemars(range(min = 0, max = 10000))]
            pub limit: Option<i64>,
            #[schemars(description = "Only return names containing this text (case-insensitive)")]
            #[serde(alias = "query")]
            pub filter: Option<String>,
            #[schemars(
                description = "Filter names by regular expression instead of substring. \
                               Mutually exclusive with 'filter'."
            )]
            #[serde(alias = "name_regex")]
            pub regex: Option<String>,
            $(
                #[schemars(
                    description = "Only return symbols imported through a module/segment whose \
                                   name contains this text (case-insensitive)"
                )]
                pub $module: Option<String>,
            )?
            #[schemars(
                description = "Order the answer by 'address' or 'name'. Sorting reads every \
                               match before paging, so it costs a full walk of the listing."
            )]
            #[serde(default, deserialize_with = "lenient_enum")]
            pub sort_by: Option<NameSort>,
            #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
            pub descending: Option<bool>,
            #[schemars(
                description = "Timeout in seconds for this operation (default: 120, max: 600)"
            )]
            #[schemars(range(min = 0, max = 600))]
            pub timeout_secs: Option<i64>,
        }

        impl $name {
            /// Resolve into the worker-side query.
            pub fn resolve_query(&self) -> Result<NameQuery, ToolError> {
                if self.descending.unwrap_or(false) && self.sort_by.is_none() {
                    return Err(ToolError::InvalidParams(
                        "'descending' needs a 'sort_by' to reverse".to_string(),
                    ));
                }
                // `None` for a listing with no module field; the optional
                // fragment adds the real lookup for the one that has it.
                let module = None $(.or_else(|| self.$module.clone()))?;
                let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
                Ok(NameQuery {
                    offset,
                    limit,
                    filter: self.filter.clone(),
                    regex: self.regex.clone(),
                    module,
                    sort_by: self.sort_by,
                    descending: self.descending.unwrap_or(false),
                })
            }
        }
    };
}

symbol_list_request!(ImportsRequest, "imports", module);
symbol_list_request!(ExportsRequest, "exports");

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LookupFuncsRequest {
    #[schemars(description = "Function queries (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names")]
    pub queries: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListGlobalsRequest {
    #[schemars(description = "Optional filter for globals")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(
        description = "Filter names by regular expression instead of substring. Mutually \
                       exclusive with 'query'."
    )]
    #[serde(alias = "name_regex")]
    pub regex: Option<String>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum globals to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(
        description = "Order the answer by 'address' or 'name'. Sorting reads every match \
                       before paging, so it costs a full walk of the listing."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub sort_by: Option<NameSort>,
    #[schemars(description = "Reverse the sort order (default: false; needs 'sort_by')")]
    pub descending: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl ListGlobalsRequest {
    /// Resolve into the worker-side query.
    pub fn resolve_query(&self) -> Result<NameQuery, ToolError> {
        if self.descending.unwrap_or(false) && self.sort_by.is_none() {
            return Err(ToolError::InvalidParams(
                "'descending' needs a 'sort_by' to reverse".to_string(),
            ));
        }
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(NameQuery {
            offset,
            limit,
            filter: self.query.clone(),
            regex: self.regex.clone(),
            module: None,
            sort_by: self.sort_by,
            descending: self.descending.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeStringsRequest {
    #[schemars(description = "Optional filter for strings")]
    #[serde(alias = "filter")]
    pub query: Option<String>,
    #[schemars(
        description = "Filter string contents by regular expression instead of substring. \
                       Mutually exclusive with 'query'."
    )]
    pub regex: Option<String>,
    #[schemars(description = "Only return strings of at least this many characters")]
    #[schemars(range(min = 0))]
    pub min_length: Option<i64>,
    #[schemars(description = "Only return strings of at most this many characters")]
    #[schemars(range(min = 0))]
    pub max_length: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum strings to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl AnalyzeStringsRequest {
    /// Resolve into the worker-side query. Never sorts: this listing pairs
    /// each string with its xrefs, so reordering it would decouple the two.
    pub fn resolve_query(&self) -> Result<StringQuery, ToolError> {
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(StringQuery {
            offset,
            limit,
            filter: self.query.clone(),
            regex: self.regex.clone(),
            min_length: parse_optional_unsigned::<usize>(self.min_length, "min_length")?,
            max_length: parse_optional_unsigned::<usize>(self.max_length, "max_length")?,
            sort_by: None,
            descending: false,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindBytesRequest {
    #[schemars(description = "Pattern(s) to search for (string or array)")]
    #[serde(alias = "pattern", alias = "patterns")]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_max_results")]
    #[schemars(skip)]
    pub worker_max_results: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchRequest {
    #[schemars(description = "Targets to search for (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "targets")]
    pub targets: Value,
    #[schemars(
        description = "Search type: 'text', 'imm', or 'auto' (default) to decide per target"
    )]
    #[serde(alias = "type", default, deserialize_with = "lenient_enum")]
    pub kind: Option<SearchKind>,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(
        description = "Scope: search only the function containing this address. Mutually \
                       exclusive with 'segment' and 'start'/'end'."
    )]
    pub function: Option<AddressArg>,
    #[schemars(
        description = "Scope: search only this segment, by name (e.g. '.text'). Mutually \
                       exclusive with 'function' and 'start'/'end'."
    )]
    pub segment: Option<String>,
    #[schemars(
        description = "Scope: start of an explicit address range (needs 'end'). Mutually \
                       exclusive with 'function' and 'segment'."
    )]
    pub start: Option<AddressArg>,
    #[schemars(description = "Scope: exclusive end of an explicit address range (needs 'start').")]
    pub end: Option<AddressArg>,
    #[schemars(description = "Keep only matches inside executable segments (default: false)")]
    pub code_only: Option<bool>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
    #[serde(default, rename = "_worker_max_results")]
    #[schemars(skip)]
    pub worker_max_results: Option<i64>,
}

impl SearchRequest {
    /// Resolve this request's scope fields, rejecting a contradictory pair.
    pub fn resolve_scope(&self) -> Result<ScanScope, ToolError> {
        ScanScope::select(ScopeSpec {
            function: self
                .function
                .as_ref()
                .map(AddressArg::to_single)
                .transpose()?,
            segment: self.segment.clone(),
            start: self.start.as_ref().map(AddressArg::to_single).transpose()?,
            end: self.end.as_ref().map(AddressArg::to_single).transpose()?,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindInsnsRequest {
    #[schemars(description = "Instruction mnemonic(s) or sequence (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "mnemonic",
        alias = "mnemonics"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(
        description = "Treat each pattern as a regular expression matched against the whole \
                       disassembly line, instead of a substring (default: false)"
    )]
    pub regex: Option<bool>,
    #[schemars(
        description = "Scope: scan only the function containing this address. Mutually \
                       exclusive with 'segment' and 'start'/'end'."
    )]
    pub function: Option<AddressArg>,
    #[schemars(
        description = "Scope: scan only this segment, by name (e.g. '.text'). Mutually \
                       exclusive with 'function' and 'start'/'end'."
    )]
    pub segment: Option<String>,
    #[schemars(
        description = "Scope: start of an explicit address range (needs 'end'). Mutually \
                       exclusive with 'function' and 'segment'."
    )]
    pub start: Option<AddressArg>,
    #[schemars(description = "Scope: exclusive end of an explicit address range (needs 'start').")]
    pub end: Option<AddressArg>,
    #[schemars(
        description = "Maximum instructions to decode before giving up (default: 500000). \
                       The answer reports 'scan_truncated' when this is reached."
    )]
    #[schemars(range(min = 1, max = 100000000))]
    pub max_scan: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindInsnOperandsRequest {
    #[schemars(description = "Operand substring(s) to match (string/number or array)")]
    #[serde(
        alias = "pattern",
        alias = "patterns",
        alias = "query",
        alias = "queries",
        alias = "operands"
    )]
    pub patterns: Value,
    #[schemars(description = "Maximum matches to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Case-insensitive match (default: false)")]
    pub case_insensitive: Option<bool>,
    #[schemars(
        description = "Treat each pattern as a regular expression matched against the operand \
                       text, instead of a substring (default: false)"
    )]
    pub regex: Option<bool>,
    #[schemars(
        description = "Scope: scan only the function containing this address. Mutually \
                       exclusive with 'segment' and 'start'/'end'."
    )]
    pub function: Option<AddressArg>,
    #[schemars(
        description = "Scope: scan only this segment, by name (e.g. '.text'). Mutually \
                       exclusive with 'function' and 'start'/'end'."
    )]
    pub segment: Option<String>,
    #[schemars(
        description = "Scope: start of an explicit address range (needs 'end'). Mutually \
                       exclusive with 'function' and 'segment'."
    )]
    pub start: Option<AddressArg>,
    #[schemars(description = "Scope: exclusive end of an explicit address range (needs 'start').")]
    pub end: Option<AddressArg>,
    #[schemars(
        description = "Maximum instructions to decode before giving up (default: 500000). \
                       The answer reports 'scan_truncated' when this is reached."
    )]
    #[schemars(range(min = 1, max = 100000000))]
    pub max_scan: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

/// The scope and budget half of an instruction-scan request.
///
/// `find_insns` and `find_insn_operands` declare these fields separately so
/// each publishes its own descriptions, but they resolve identically — this
/// trait is what keeps the two resolutions from drifting.
pub trait InsnScanParams {
    fn patterns(&self) -> &Value;
    fn limit(&self) -> Option<i64>;
    fn case_insensitive(&self) -> Option<bool>;
    fn regex(&self) -> Option<bool>;
    fn function(&self) -> Option<&AddressArg>;
    fn segment(&self) -> Option<&str>;
    fn start(&self) -> Option<&AddressArg>;
    fn end(&self) -> Option<&AddressArg>;
    fn max_scan(&self) -> Option<i64>;

    /// Resolve into the scan the worker runs, rejecting a contradictory scope
    /// or an unparseable bound before a database lock is taken.
    fn resolve_scan(&self) -> Result<InsnScanRequest, ToolError> {
        let patterns = value_to_strings(self.patterns())?;
        if patterns.is_empty() {
            return Err(ToolError::InvalidParams("empty patterns".to_string()));
        }

        let spec = ScopeSpec {
            function: self.function().map(AddressArg::to_single).transpose()?,
            segment: self.segment().map(str::to_string),
            start: self.start().map(AddressArg::to_single).transpose()?,
            end: self.end().map(AddressArg::to_single).transpose()?,
        };

        Ok(InsnScanRequest {
            patterns,
            // Clamped rather than parsed, which also makes the ceiling real: the
            // schema has published `max: 10000` all along while the code took
            // whatever arrived.
            max_results: vibrev_kit::page::capped(self.limit(), 100, 10_000),
            case_insensitive: self.case_insensitive().unwrap_or(false),
            regex: self.regex().unwrap_or(false),
            scope: ScanScope::select(spec)?,
            max_scan: parse_optional_unsigned::<usize>(self.max_scan(), "max_scan")?
                .unwrap_or(DEFAULT_MAX_SCAN),
        })
    }
}

macro_rules! impl_insn_scan_params {
    ($($ty:ty),+ $(,)?) => {
        $(impl InsnScanParams for $ty {
            fn patterns(&self) -> &Value {
                &self.patterns
            }
            fn limit(&self) -> Option<i64> {
                self.limit
            }
            fn case_insensitive(&self) -> Option<bool> {
                self.case_insensitive
            }
            fn regex(&self) -> Option<bool> {
                self.regex
            }
            fn function(&self) -> Option<&AddressArg> {
                self.function.as_ref()
            }
            fn segment(&self) -> Option<&str> {
                self.segment.as_deref()
            }
            fn start(&self) -> Option<&AddressArg> {
                self.start.as_ref()
            }
            fn end(&self) -> Option<&AddressArg> {
                self.end.as_ref()
            }
            fn max_scan(&self) -> Option<i64> {
                self.max_scan
            }
        })+
    };
}

impl_insn_scan_params!(FindInsnsRequest, FindInsnOperandsRequest);

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindPathsRequest {
    #[schemars(description = "Start address (string/number)")]
    pub start: AddressArg,
    #[schemars(description = "End address (string/number)")]
    pub end: AddressArg,
    #[schemars(description = "Maximum paths to return (default: 8)")]
    #[schemars(range(min = 1, max = 1024))]
    pub max_paths: Option<i64>,
    #[schemars(description = "Maximum path depth (default: 64)")]
    #[schemars(range(min = 1, max = 256))]
    pub max_depth: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CallGraphRequest {
    #[schemars(description = "Root function address(es) (string/number or array)")]
    #[serde(
        alias = "root",
        alias = "roots",
        alias = "addr",
        alias = "address",
        alias = "addrs"
    )]
    pub roots: AddressArg,
    #[schemars(description = "Maximum depth (default: 2)")]
    #[schemars(range(min = 1, max = 256))]
    pub max_depth: Option<i64>,
    #[schemars(description = "Maximum nodes (default: 256)")]
    #[schemars(range(min = 1, max = 10000))]
    pub max_nodes: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct XrefMatrixRequest {
    #[schemars(description = "Addresses to include in matrix (string/number or array)")]
    #[serde(alias = "addr", alias = "address", alias = "addresses")]
    pub addrs: AddressArg,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExportFuncsRequest {
    #[schemars(description = "Function address(es) to export (optional)")]
    #[serde(
        alias = "addrs",
        alias = "addr",
        alias = "address",
        alias = "functions"
    )]
    pub addrs: Option<Value>,
    #[schemars(description = "Offset for pagination (default: 0)")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum functions to return (default: 100)")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Export format (only json supported)")]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub format: Option<ExportFormat>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MakeSignatureRequest {
    #[schemars(description = "Address(es) to build a signature for (string/number or array)")]
    #[serde(alias = "addr", alias = "addrs", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(
        description = "Cover exactly [address, end) instead of growing the pattern until it is \
                       unique. Only valid with a single address."
    )]
    pub end: Option<AddressArg>,
    #[schemars(
        description = "Output syntax: 'ida' (default, 'E8 ? ? 48'), 'x64dbg' ('E8 ?? ?? 48'), \
                       'mask' (escaped bytes plus a mask string), or 'bitmask' (C array plus a \
                       binary mask)."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub format: Option<SignatureFormat>,
    #[schemars(
        description = "Wildcard instruction operands so the pattern survives relocation \
                       (default: true)"
    )]
    pub wildcard_operands: Option<bool>,
    #[schemars(
        description = "Give up once the pattern reaches this many bytes (default: 1000). The \
                       answer reports 'truncated' when the ceiling was hit without becoming \
                       unique."
    )]
    #[schemars(range(min = 1, max = 100000))]
    pub max_length: Option<i64>,
    #[schemars(description = "Timeout in seconds for this operation (default: 120, max: 600)")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl MakeSignatureRequest {
    /// Resolve into one worker-side request per address.
    ///
    /// `end` describes a single range, so pairing it with several addresses is
    /// an error rather than a silent broadcast of the same end to each.
    pub fn resolve(&self) -> Result<Vec<SignatureRequest>, ToolError> {
        let addrs = self.address.to_addresses()?;
        if addrs.is_empty() {
            return Err(ToolError::InvalidParams("no address given".to_string()));
        }
        let end = self.end.as_ref().map(AddressArg::to_single).transpose()?;
        if end.is_some() && addrs.len() > 1 {
            return Err(ToolError::InvalidParams(
                "'end' describes one range, so it cannot be combined with several addresses"
                    .to_string(),
            ));
        }

        let max_length = parse_optional_unsigned::<usize>(self.max_length, "max_length")?
            .unwrap_or(1000)
            .max(1);
        let wildcard_operands = self.wildcard_operands.unwrap_or(true);
        let format = self.format.unwrap_or_default();

        Ok(addrs
            .into_iter()
            .map(|address| SignatureRequest {
                address,
                end,
                wildcard_operands,
                max_length,
                format,
            })
            .collect())
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetIntRequest {
    #[schemars(description = "Address(es) to read (string/number or array)")]
    pub address: AddressArg,
    #[schemars(
        description = "Integer type: i8/u8/i16/u16/i32/u32/i64/u64, with an optional 'le' or                        'be' suffix (e.g. 'u32be'). Without a suffix the database's own byte                        order is used."
    )]
    #[serde(alias = "type")]
    pub ty: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutIntRequest {
    #[schemars(description = "Address to write to")]
    pub address: AddressArg,
    #[schemars(
        description = "Integer type: i8/u8/i16/u16/i32/u32/i64/u64, with an optional 'le' or                        'be' suffix (e.g. 'u32be'). Without a suffix the database's own byte                        order is used."
    )]
    #[serde(alias = "type")]
    pub ty: String,
    #[schemars(
        description = "Value to write, as a string: decimal or 0x-hex, negative allowed for                        signed types. A string because JSON numbers cannot carry the far ends                        of i64/u64 without loss."
    )]
    pub value: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringRequest {
    #[schemars(description = "Address(es) to read string from (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(description = "Maximum length to read (default: 256)")]
    #[schemars(range(min = 1, max = 4096))]
    pub max_len: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetGlobalValueRequest {
    #[schemars(description = "Global name(s) or address(es) (string/number or array)")]
    #[serde(alias = "query", alias = "queries", alias = "names", alias = "addrs")]
    pub query: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IntConvertRequest {
    #[schemars(description = "Values to convert (string/number or array)")]
    #[serde(alias = "input", alias = "inputs")]
    pub inputs: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PseudocodeAtRequest {
    #[schemars(description = "Address(es) to get pseudocode for (string/number or array)")]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses")]
    pub address: AddressArg,
    #[schemars(description = "Optional end address for range query (for basic blocks)")]
    pub end_address: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolCatalogRequest {
    #[schemars(
        description = "What you're trying to accomplish (e.g., 'find all callers of a function')"
    )]
    pub query: Option<String>,
    #[schemars(
        description = "Filter by category. The schema lists the permitted values; \
        `debug` and `ui` were named here for years and have never existed."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub category: Option<CatalogCategory>,
    #[schemars(description = "Maximum number of tools to return (default: 7)")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ToolHelpRequest {
    #[schemars(description = "Name of the tool to get help for")]
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RecentOperationsRequest {
    #[schemars(description = "Maximum recent events to return (default: 20, max: 50)")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunScriptRequest {
    #[schemars(description = "Inline Python code (mutually exclusive with 'file').")]
    pub code: Option<String>,
    #[schemars(
        description = "Path to a .py file (mutually exclusive with 'code'). Read server-side."
    )]
    pub file: Option<String>,
    #[schemars(description = "Execution timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskStatusRequest {
    #[schemars(description = "Task ID returned by open_dsc (e.g. 'dsc-abc123')")]
    pub task_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenDscRequest {
    #[schemars(description = "Path to the dyld_shared_cache file.")]
    pub path: String,
    #[schemars(description = "CPU arch (e.g. 'arm64e', 'arm64', 'x86_64h').")]
    pub arch: String,
    #[schemars(description = "Primary dylib path (e.g. '/usr/lib/libobjc.A.dylib').")]
    pub module: String,
    #[schemars(description = "Additional frameworks to load (absolute DSC paths).")]
    pub frameworks: Option<Vec<String>>,
    #[schemars(description = "IDA version 8 or 9 (default 9).")]
    #[schemars(range(min = 8, max = 9))]
    pub ida_version: Option<i64>,
    #[schemars(
        description = "Path for idat's log file (-L). Used only by the legacy pre-IDA-9.4 DSC path."
    )]
    pub log_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscAddDylibRequest {
    #[schemars(
        description = "DSC-internal dylib path (absolute, e.g. '/usr/lib/libSystem.B.dylib')."
    )]
    pub module: String,
    #[schemars(description = "Timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscAddRegionRequest {
    #[schemars(description = "Single region address (hex '0x...' or decimal).")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: AddressArg,
    #[schemars(description = "Timeout in seconds (default 300, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscListImagesRequest {
    #[schemars(
        description = "Keep only images whose path contains this text (case-folded substring)."
    )]
    #[serde(alias = "query")]
    pub filter: Option<String>,
    #[schemars(
        description = "Keep only images whose path matches this regular expression. Name at \
                       most one of 'filter' and 'regex'."
    )]
    pub regex: Option<String>,
    #[schemars(
        description = "Keep only images already mapped into the database (default false). A \
                       freshly opened DSC has none: the loader maps the header only."
    )]
    pub loaded_only: Option<bool>,
    #[schemars(description = "Offset for pagination (default 0).")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum images to return (1-10000, default 100).")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl DscListImagesRequest {
    pub fn resolve_query(&self) -> Result<DscImageQuery, ToolError> {
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        Ok(DscImageQuery {
            offset,
            limit,
            filter: crate::non_empty_trimmed(self.filter.as_deref()).map(str::to_string),
            regex: crate::non_empty_trimmed(self.regex.as_deref()).map(str::to_string),
            loaded_only: self.loaded_only.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscImageDepsRequest {
    #[schemars(
        description = "DSC-internal dylib path (absolute, e.g. '/usr/lib/libSystem.B.dylib')."
    )]
    pub module: String,
    #[schemars(
        description = "Recursion depth: 1 = direct dependencies only (default), -1 = the whole \
                       transitive closure."
    )]
    #[schemars(range(min = -1, max = 64))]
    pub depth: Option<i64>,
    #[schemars(description = "Offset for pagination (default 0).")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum images to return (1-10000, default 100).")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 10000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl DscImageDepsRequest {
    pub fn resolve_query(&self) -> Result<DscDepsQuery, ToolError> {
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 10_000)?;
        // -1 is a sentinel for "unlimited", so this one cannot go through
        // parse_optional_unsigned. The schema pins the rest of the range.
        let depth = match self.depth {
            None => 1,
            Some(depth) if (-1..=64).contains(&depth) => depth as i32,
            Some(depth) => {
                return Err(ToolError::InvalidParams(format!(
                    "depth must be -1 (unlimited) or 0..=64, got {depth}"
                )));
            }
        };
        Ok(DscDepsQuery {
            offset,
            limit,
            module: self.module.trim().to_string(),
            depth,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscFindSymbolsRequest {
    #[schemars(description = "Substring to look for in symbol names. Must not be empty.")]
    #[serde(alias = "query", alias = "name")]
    pub needle: String,
    #[schemars(
        description = "Skip the export tables of images that are not mapped in yet (default \
                       false, i.e. search the whole cache)."
    )]
    pub loaded_images_only: Option<bool>,
    #[schemars(description = "Match case-insensitively (default false).")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default 0).")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum matches to return (1-1000, default 100).")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 1000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

/// A search needle IDA can take: non-empty, and free of the interior NUL that
/// would fail the C-string conversion inside idalib.
///
/// The NUL check belongs here and not in the handler. idalib reports that
/// conversion failure exactly the way it reports "nothing matched", and the
/// handler reads the latter as an empty result — so a needle that could only
/// ever fail has to be turned away before it reaches that reading.
fn dsc_needle(raw: &str) -> Result<String, ToolError> {
    let needle = raw.trim().to_string();
    if needle.is_empty() {
        return Err(ToolError::InvalidParams(
            "needle must not be empty".to_string(),
        ));
    }
    if needle.contains('\0') {
        return Err(ToolError::InvalidParams(
            "needle must not contain a NUL character".to_string(),
        ));
    }
    Ok(needle)
}

impl DscFindSymbolsRequest {
    pub fn resolve_search(&self) -> Result<DscSymbolSearch, ToolError> {
        let needle = dsc_needle(&self.needle)?;
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 1_000)?;
        Ok(DscSymbolSearch {
            offset,
            limit,
            needle,
            loaded_images_only: self.loaded_images_only.unwrap_or(false),
            case_insensitive: self.case_insensitive.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscFindStringsRequest {
    #[schemars(description = "Substring to look for in the cache's bytes. Must not be empty.")]
    #[serde(alias = "query", alias = "content")]
    pub needle: String,
    #[schemars(
        description = "Where to scan: 'images' (default) reads the images' own contents, \
                       'files' reads whole cache files including bytes no image claims."
    )]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub scope: Option<DscStringScope>,
    #[schemars(
        description = "Under scope='images': scan every section, not just data sections \
                       (default false). Ignored when scope='files'."
    )]
    pub all_sections: Option<bool>,
    #[schemars(
        description = "Under scope='files': also scan the '.symbols' pool (default false). \
                       Ignored when scope='images'."
    )]
    pub include_symbols: Option<bool>,
    #[schemars(
        description = "Under scope='files': also scan branch-mapping files (default false). \
                       Ignored when scope='images'."
    )]
    pub include_branch_mappings: Option<bool>,
    #[schemars(
        description = "Under scope='files': also scan other adjacent files (default false). \
                       Ignored when scope='images'."
    )]
    pub include_other: Option<bool>,
    #[schemars(description = "Match case-insensitively (default false).")]
    pub case_insensitive: Option<bool>,
    #[schemars(description = "Offset for pagination (default 0).")]
    #[schemars(range(min = 0))]
    pub offset: Option<i64>,
    #[schemars(description = "Maximum matches to return (1-1000, default 100).")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 1000))]
    pub limit: Option<i64>,
    #[schemars(description = "Timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

impl DscFindStringsRequest {
    pub fn resolve_search(&self) -> Result<DscStringSearch, ToolError> {
        let needle = dsc_needle(&self.needle)?;
        let (offset, limit) = page_bounds(self.offset, self.limit, 100, 1_000)?;
        Ok(DscStringSearch {
            offset,
            limit,
            needle,
            scope: self.scope.unwrap_or_default(),
            all_sections: self.all_sections.unwrap_or(false),
            include_symbols: self.include_symbols.unwrap_or(false),
            include_branch_mappings: self.include_branch_mappings.unwrap_or(false),
            include_other: self.include_other.unwrap_or(false),
            case_insensitive: self.case_insensitive.unwrap_or(false),
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DscRegionAtRequest {
    #[schemars(description = "Single address to resolve (hex '0x...' or decimal).")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: AddressArg,
    #[schemars(description = "Timeout in seconds (default 120, max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

// ---------------------------------------------------------------------------
// Composite tools
// ---------------------------------------------------------------------------
//
// Every knob below is a *ceiling*, never a page cursor: composite tools answer
// once, completely, and say in their `limits` block what they had to leave out.
// A caller that needs the remainder pages through the primitive tool instead.

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SurveyBinaryRequest {
    #[schemars(
        description = "'standard' (default) runs the per-function metrics pass that ranks \
        interesting_strings/interesting_functions and builds callgraph_summary. 'minimal' skips \
        it — much faster on large firmware, but those three blocks are then absent."
    )]
    #[serde(alias = "detail_level", default, deserialize_with = "lenient_enum")]
    pub detail: Option<SurveyDetail>,
    #[schemars(
        description = "Maximum functions to scan and profile (default and hard cap: 10000)."
    )]
    #[schemars(range(min = 1, max = 10000))]
    pub max_functions: Option<i64>,
    #[schemars(description = "Maximum strings to scan and rank (default and hard cap: 5000).")]
    #[schemars(range(min = 0, max = 5000))]
    pub max_strings: Option<i64>,
    #[schemars(
        description = "Maximum imports to scan and categorize (default and hard cap: 10000)."
    )]
    #[schemars(range(min = 0, max = 10000))]
    pub max_imports: Option<i64>,
    #[schemars(description = "Maximum exports/names to count (default and hard cap: 10000).")]
    #[schemars(range(min = 0, max = 10000))]
    pub max_exports: Option<i64>,
    #[schemars(
        description = "How many entries each interesting_* list and callgraph_summary.root_functions \
        keeps (default 15, max 200)."
    )]
    #[serde(alias = "highlight_limit")]
    #[schemars(range(min = 0, max = 200))]
    pub top: Option<i64>,
    #[schemars(
        description = "Timeout in seconds for each underlying query (default: 120, max: 600)"
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFunctionRequest {
    #[schemars(
        description = "Target address(es) (string/number or array). Any address inside a function \
        resolves to that function. Max 32 targets per call."
    )]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses", alias = "ea")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to analyze (alternative to address).")]
    #[serde(alias = "name", alias = "function", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Offset added to the resolved name address (default: 0).")]
    pub offset: Option<i64>,
    #[schemars(description = "Include decompiler pseudocode (default: true).")]
    #[serde(alias = "include_decompile")]
    pub include_pseudocode: Option<bool>,
    #[schemars(description = "Include the instruction listing (default: true).")]
    #[serde(alias = "include_disasm")]
    pub include_disassembly: Option<bool>,
    #[schemars(
        description = "Include the strings referenced from inside the function (default: true). \
        Costs one scan of the database's string index — turn it off on string-heavy binaries."
    )]
    pub include_strings: Option<bool>,
    #[schemars(description = "Include the stack frame layout (default: true).")]
    #[serde(alias = "include_frame")]
    pub include_stack_frame: Option<bool>,
    #[schemars(description = "Include the control-flow graph nodes (default: true).")]
    #[serde(alias = "include_blocks")]
    pub include_basic_blocks: Option<bool>,
    #[schemars(description = "Maximum instructions per listing (default: 400, max: 5000).")]
    #[serde(alias = "count")]
    #[schemars(range(min = 0, max = 5000))]
    pub max_instructions: Option<i64>,
    #[schemars(description = "Maximum callers to list (default: 100, max: 1000).")]
    #[schemars(range(min = 0, max = 1000))]
    pub max_callers: Option<i64>,
    #[schemars(description = "Maximum callees to list (default: 100, max: 1000).")]
    #[schemars(range(min = 0, max = 1000))]
    pub max_callees: Option<i64>,
    #[schemars(description = "Maximum basic blocks to list (default: 200, max: 2000).")]
    #[schemars(range(min = 0, max = 2000))]
    pub max_blocks: Option<i64>,
    #[schemars(
        description = "Maximum strings to scan when resolving referenced_strings \
        (default and hard cap: 5000)."
    )]
    #[schemars(range(min = 0, max = 5000))]
    pub max_strings_scanned: Option<i64>,
    #[schemars(
        description = "Timeout in seconds for each underlying query (default: 120, max: 600)"
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeComponentRequest {
    #[schemars(
        description = "Function names or addresses that form the component (string, number, \
        comma-separated string, or array). Each token is tried as an address first and as a \
        function name if that fails. Empty list is an error; any token that cannot be resolved \
        fails the whole call. Max 32 distinct functions per call."
    )]
    #[serde(alias = "address", alias = "functions")]
    pub addrs: Option<Value>,
    #[schemars(
        description = "Timeout in seconds for each underlying query (default: 120, max: 600)"
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

/// Mutation `diff_before_after` applies before the second decompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffAction {
    RenameFunc,
    SetType,
    SetComment,
}

/// Which way `trace_data_flow` walks xrefs. Not a call-graph direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TraceDirection {
    Forward,
    Backward,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiffBeforeAfterRequest {
    #[schemars(
        description = "Function address (string/number). Any address inside a function \
        resolves to that function."
    )]
    #[serde(alias = "ea", alias = "addr", alias = "addresses")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name (alternative to address).")]
    #[serde(alias = "function", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(description = "Mutation to apply: rename_func, set_type, or set_comment.")]
    pub action: DiffAction,
    #[schemars(description = "New function name. Required when action=rename_func.")]
    pub name: Option<String>,
    #[schemars(description = "Function prototype to apply. Required when action=set_type.")]
    pub decl: Option<String>,
    #[schemars(description = "Comment text. Required when action=set_comment.")]
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TraceDataFlowRequest {
    #[schemars(description = "Single start address (string/number). Not a list.")]
    #[serde(alias = "ea", alias = "addr")]
    pub address: AddressArg,
    #[schemars(description = "Walk xrefs_from (forward, default) or xrefs_to (backward).")]
    #[serde(default, deserialize_with = "lenient_enum")]
    pub direction: Option<TraceDirection>,
    #[schemars(description = "BFS depth (default 5, clamped to 1..=20).")]
    #[schemars(range(min = 1, max = 20))]
    pub max_depth: Option<i64>,
    #[schemars(description = "Timeout in seconds for each xref page (max 600).")]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FuncProfileRequest {
    #[schemars(
        description = "Target address(es) (string/number or array). Any address inside a function \
        resolves to that function. Max 32 targets per call."
    )]
    #[serde(alias = "addrs", alias = "addr", alias = "addresses", alias = "ea")]
    pub address: Option<AddressArg>,
    #[schemars(description = "Function or symbol name to profile (alternative to address).")]
    #[serde(alias = "name", alias = "function", alias = "symbol")]
    pub target_name: Option<String>,
    #[schemars(
        description = "Include callers/callees/strings lists (default: false; counts only)."
    )]
    pub include_lists: Option<bool>,
    #[schemars(description = "Cap on each included list (default: 20, max: 200).")]
    #[schemars(range(min = 0, max = 200))]
    pub max_items: Option<i64>,
    #[schemars(
        description = "Timeout in seconds for the string-index scan (default: 120, max: 600)"
    )]
    #[schemars(range(min = 0, max = 600))]
    pub timeout_secs: Option<i64>,
}
