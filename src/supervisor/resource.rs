use super::session::SessionManager;
use crate::error::ToolError;
use percent_encoding::percent_decode_str;
use rmcp::model::{ReadResourceResponse, ReadResourceResult, ResourceContents};
use rmcp::ErrorData as McpError;
use serde_json::{json, Map, Value};
use std::path::Path;
use url::Url;

const RESOURCE_LIMIT: u64 = 10_000;

#[derive(Debug, PartialEq)]
enum ResourceKind {
    Databases,
    Cursor,
    Selection,
    Metadata,
    Segments,
    Entrypoints,
    Types,
    Structs,
    Struct(String),
    Import(String),
    Export(String),
    XrefsFrom(String),
}

#[derive(Debug, PartialEq)]
struct ResourceRequest {
    kind: ResourceKind,
    database: Option<String>,
}

impl ResourceRequest {
    fn parse(uri: &str) -> Result<Self, McpError> {
        let parsed = Url::parse(uri).map_err(|error| {
            McpError::invalid_params(
                format!("Invalid resource URI '{uri}': {error}"),
                Some(json!({"uri": uri})),
            )
        })?;
        if parsed.scheme() != "ida" {
            return Err(resource_not_found(uri));
        }

        let host = parsed.host_str().unwrap_or_default();
        let segments = parsed
            .path_segments()
            .into_iter()
            .flatten()
            .filter(|segment| !segment.is_empty())
            .map(|segment| {
                percent_decode_str(segment)
                    .decode_utf8()
                    .map(|value| value.into_owned())
                    .map_err(|error| {
                        McpError::invalid_params(
                            format!("Invalid UTF-8 in resource URI '{uri}': {error}"),
                            Some(json!({"uri": uri})),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let kind = match (host, segments.as_slice()) {
            ("databases", []) => ResourceKind::Databases,
            ("cursor", []) => ResourceKind::Cursor,
            ("selection", []) => ResourceKind::Selection,
            ("idb", [part]) if part == "metadata" => ResourceKind::Metadata,
            ("idb", [part]) if part == "segments" => ResourceKind::Segments,
            ("idb", [part]) if part == "entrypoints" => ResourceKind::Entrypoints,
            ("types", []) => ResourceKind::Types,
            ("structs", []) => ResourceKind::Structs,
            ("struct", [name]) => ResourceKind::Struct(name.clone()),
            ("import", [name]) => ResourceKind::Import(name.clone()),
            ("export", [name]) => ResourceKind::Export(name.clone()),
            ("xrefs", [direction, address]) if direction == "from" => {
                ResourceKind::XrefsFrom(address.clone())
            }
            _ => return Err(resource_not_found(uri)),
        };

        let mut database = None;
        for (key, value) in parsed.query_pairs() {
            if key != "database" {
                continue;
            }
            if value.is_empty() {
                return Err(McpError::invalid_params(
                    "Resource URI database query parameter must not be empty",
                    Some(json!({"uri": uri})),
                ));
            }
            if database.replace(value.into_owned()).is_some() {
                return Err(McpError::invalid_params(
                    "Resource URI contains more than one database query parameter",
                    Some(json!({"uri": uri})),
                ));
            }
        }

        Ok(Self { kind, database })
    }
}

pub async fn read(sessions: &SessionManager, uri: &str) -> Result<ReadResourceResponse, McpError> {
    let request = ResourceRequest::parse(uri)?;
    let value = match request.kind {
        ResourceKind::Databases => {
            let databases = sessions.list().await;
            json!({"count": databases.len(), "databases": databases})
        }
        ResourceKind::Cursor => json!({"addr": Value::Null}),
        ResourceKind::Selection => json!({"selection": Value::Null}),
        kind => {
            let database = resolve_database(sessions, request.database.as_deref(), uri).await?;
            read_worker_resource(sessions, &database, kind, uri).await?
        }
    };
    json_response(uri, value)
}

async fn resolve_database(
    sessions: &SessionManager,
    requested: Option<&str>,
    uri: &str,
) -> Result<String, McpError> {
    let databases = sessions.list().await;
    if let Some(requested) = requested {
        return databases
            .iter()
            .any(|database| database.session_id == requested)
            .then(|| requested.to_string())
            .ok_or_else(|| {
                McpError::resource_not_found(
                    format!("Unknown database session '{requested}'"),
                    Some(json!({"uri": uri, "database": requested})),
                )
            });
    }

    match databases.as_slice() {
        [database] => Ok(database.session_id.clone()),
        [] => Err(McpError::invalid_params(
            "This resource requires an open database. Call idb_open first.",
            Some(json!({"uri": uri})),
        )),
        _ => Err(McpError::invalid_params(
            "This resource is ambiguous because multiple databases are open. Append '?database=<session_id>' to the URI.",
            Some(json!({
                "uri": uri,
                "databases": databases
                    .iter()
                    .map(|database| database.session_id.as_str())
                    .collect::<Vec<_>>(),
            })),
        )),
    }
}

async fn read_worker_resource(
    sessions: &SessionManager,
    database: &str,
    kind: ResourceKind,
    uri: &str,
) -> Result<Value, McpError> {
    match kind {
        ResourceKind::Metadata => {
            let value = call_native(sessions, database, "idb_meta", Map::new(), uri).await?;
            Ok(metadata_resource(&value))
        }
        ResourceKind::Segments => {
            let value = call_native(sessions, database, "segments", Map::new(), uri).await?;
            Ok(segments_resource(&value))
        }
        ResourceKind::Entrypoints => entrypoints_resource(sessions, database, uri).await,
        ResourceKind::Types => {
            let value = call_native(
                sessions,
                database,
                "local_types",
                paginated_arguments(),
                uri,
            )
            .await?;
            Ok(types_resource(&value))
        }
        ResourceKind::Structs => {
            let value =
                call_native(sessions, database, "structs", paginated_arguments(), uri).await?;
            Ok(structs_resource(&value))
        }
        ResourceKind::Struct(name) => struct_resource(sessions, database, &name, uri).await,
        ResourceKind::Import(name) => import_resource(sessions, database, &name, uri).await,
        ResourceKind::Export(name) => export_resource(sessions, database, &name, uri).await,
        ResourceKind::XrefsFrom(address) => {
            xrefs_from_resource(sessions, database, &address, uri).await
        }
        ResourceKind::Databases | ResourceKind::Cursor | ResourceKind::Selection => {
            unreachable!("supervisor-only resources are handled before worker routing")
        }
    }
}

async fn call_native(
    sessions: &SessionManager,
    database: &str,
    tool: &str,
    arguments: Map<String, Value>,
    uri: &str,
) -> Result<Value, McpError> {
    sessions
        .call_native(database, tool, arguments, None)
        .await
        .map_err(|error| worker_error(database, uri, error))
}

fn paginated_arguments() -> Map<String, Value> {
    Map::from_iter([
        ("offset".to_string(), json!(0)),
        ("limit".to_string(), json!(RESOURCE_LIMIT)),
    ])
}

/// Every native tool this module reads a list out of, and the object key that
/// list sits under when the tool answers with an object root.
///
/// **The roots are not uniform, and that is not an oversight.** Every
/// statistics tool carries a mandatory `analysis_coverage` block; a tool that
/// already has an object root just carries one more field, while a tool whose
/// answer would be a bare array needs an object root to have somewhere to put
/// it. So `imports` and `exports` answer with `{imports|exports,
/// analysis_coverage}` while `segments` and `entrypoints` answer with bare
/// arrays.
///
/// Reading a fixed root breaks `ida://import/<name>` and `ida://export/<name>`
/// silently: `as_array()` on an object root is `None`, the search runs over an
/// empty list, and every lookup answers "not found" — for every name,
/// including ones the `imports`/`exports` tools just returned. Shape
/// assertions on `tools/*` alone cannot catch that; the `resources/*` face
/// needs its own.
///
/// This table is what [`tool_list`] consults, so a call site cannot disagree
/// with it, and `tests/tool_surface.rs` checks every entry against the tool's
/// advertised `outputSchema` — that check runs without IDA and fails the next
/// time a tool changes root without this module hearing about it.
pub const RESOURCE_LIST_SOURCES: &[(&str, &str)] = &[
    ("entrypoints", "entrypoints"),
    ("exports", "exports"),
    ("imports", "imports"),
    ("local_types", "types"),
    ("segments", "segments"),
    ("structs", "structs"),
    ("xrefs_from", "xrefs"),
];

/// The list inside `value`, whichever root `tool` answers with.
///
/// A bare array is taken as-is; an object root is indexed by the key
/// [`RESOURCE_LIST_SOURCES`] records for that tool. Accepting both is
/// deliberate — this module reads seven tools that do not agree on one root,
/// and the alternative is seven chances to pick the wrong one.
fn tool_list<'a>(value: &'a Value, tool: &str) -> &'a [Value] {
    const EMPTY: &[Value] = &[];
    let key = RESOURCE_LIST_SOURCES
        .iter()
        .find(|(name, _)| *name == tool)
        .map_or(tool, |(_, key)| *key);
    value
        .as_array()
        .or_else(|| value.get(key).and_then(Value::as_array))
        .map_or(EMPTY, Vec::as_slice)
}

fn metadata_resource(value: &Value) -> Value {
    let input_path = value
        .get("input_file_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let module = Path::new(input_path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(input_path);
    let min_address = value
        .get("min_address")
        .and_then(address_number)
        .unwrap_or(0);
    let max_address = value
        .get("max_address")
        .and_then(address_number)
        .unwrap_or(min_address);
    let file_size = value
        .get("input_file_size")
        .and_then(Value::as_u64)
        .map_or_else(|| "unavailable".to_string(), |size| format!("{size:#x}"));

    json!({
        "path": input_path,
        "module": module,
        "base": value
            .get("base_address")
            .cloned()
            .unwrap_or_else(|| json!("0x0")),
        "size": format!("{:#x}", max_address.saturating_sub(min_address)),
        "md5": value.get("md5").cloned().unwrap_or_else(|| json!("unavailable")),
        "sha256": value
            .get("sha256")
            .cloned()
            .unwrap_or_else(|| json!("unavailable")),
        "crc32": "unavailable",
        "filesize": file_size,
        "arch": value.get("processor").cloned().unwrap_or(Value::Null),
        "bits": value.get("bits").cloned().unwrap_or(Value::Null),
    })
}

fn segments_resource(value: &Value) -> Value {
    Value::Array(
        tool_list(value, "segments")
            .iter()
            .map(|segment| {
                json!({
                    "name": segment.get("name").cloned().unwrap_or_default(),
                    "start": segment.get("start").cloned().unwrap_or(Value::Null),
                    "end": segment.get("end").cloned().unwrap_or(Value::Null),
                    "size": segment
                        .get("size")
                        .and_then(Value::as_u64)
                        .map_or(Value::Null, |size| json!(format!("{size:#x}"))),
                    "permissions": segment
                        .get("permissions")
                        .cloned()
                        .unwrap_or_else(|| json!("---")),
                })
            })
            .collect(),
    )
}

async fn entrypoints_resource(
    sessions: &SessionManager,
    database: &str,
    uri: &str,
) -> Result<Value, McpError> {
    let entrypoints = call_native(sessions, database, "entrypoints", Map::new(), uri).await?;
    let addresses = tool_list(&entrypoints, "entrypoints").to_vec();
    let queries = addresses
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let lookups = if queries.is_empty() {
        json!({"results": []})
    } else {
        call_native(
            sessions,
            database,
            "lookup_funcs",
            Map::from_iter([("queries".to_string(), json!(queries))]),
            uri,
        )
        .await?
    };
    let lookup_results = lookups
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    Ok(Value::Array(
        addresses
            .into_iter()
            .enumerate()
            .map(|(index, address)| {
                let name = lookup_results
                    .get(index)
                    .and_then(|result| result.pointer("/result/name"))
                    .cloned()
                    .unwrap_or(Value::Null);
                json!({
                    "addr": address,
                    "name": name,
                    "ordinal": index + 1,
                })
            })
            .collect(),
    ))
}

fn types_resource(value: &Value) -> Value {
    Value::Array(
        tool_list(value, "local_types")
            .iter()
            .map(|item| {
                json!({
                    "ordinal": item.get("ordinal").cloned().unwrap_or(Value::Null),
                    "name": item.get("name").cloned().unwrap_or_default(),
                    "type": item.get("decl").cloned().unwrap_or_default(),
                })
            })
            .collect(),
    )
}

fn structs_resource(value: &Value) -> Value {
    Value::Array(
        tool_list(value, "structs")
            .iter()
            .map(|item| {
                json!({
                    "name": item.get("name").cloned().unwrap_or_default(),
                    "size": item
                        .get("size")
                        .and_then(Value::as_u64)
                        .map_or(Value::Null, |size| json!(format!("{size:#x}"))),
                    "is_union": item
                        .get("is_union")
                        .cloned()
                        .unwrap_or(Value::Bool(false)),
                })
            })
            .collect(),
    )
}

async fn struct_resource(
    sessions: &SessionManager,
    database: &str,
    name: &str,
    uri: &str,
) -> Result<Value, McpError> {
    let value = sessions
        .call_native(
            database,
            "struct_info",
            Map::from_iter([("name".to_string(), json!(name))]),
            None,
        )
        .await;
    let value = match value {
        Ok(value) => value,
        Err(error) if is_missing_struct(&error) => {
            return Ok(json!({"error": format!("Structure not found: {name}")}));
        }
        Err(error) => return Err(worker_error(database, uri, error)),
    };
    let members = value
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|member| {
            json!({
                "name": member.get("name").cloned().unwrap_or_default(),
                "offset": member
                    .get("offset")
                    .and_then(Value::as_u64)
                    .map_or(Value::Null, |offset| json!(format!("{offset:#x}"))),
                "size": member
                    .get("size")
                    .and_then(Value::as_u64)
                    .map_or(Value::Null, |size| json!(format!("{size:#x}"))),
                "type": member
                    .get("type_name")
                    .cloned()
                    .unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "name": value.get("name").cloned().unwrap_or_else(|| json!(name)),
        "size": value
            .get("size")
            .and_then(Value::as_u64)
            .map_or(Value::Null, |size| json!(format!("{size:#x}"))),
        "members": members,
    }))
}

async fn import_resource(
    sessions: &SessionManager,
    database: &str,
    name: &str,
    uri: &str,
) -> Result<Value, McpError> {
    let imports = call_native(sessions, database, "imports", paginated_arguments(), uri).await?;
    Ok(import_entry(&imports, name))
}

fn import_entry(imports: &Value, name: &str) -> Value {
    let found = tool_list(imports, "imports").iter().find(|item| {
        item.get("name").and_then(Value::as_str) == Some(name)
            || item
                .get("ordinal")
                .and_then(Value::as_u64)
                .is_some_and(|ordinal| format!("ord_{ordinal}") == name)
    });
    found.map_or_else(
        || json!({"error": format!("Import not found: {name}")}),
        |item| {
            json!({
                "addr": item.get("address").cloned().unwrap_or(Value::Null),
                "name": item.get("name").cloned().unwrap_or_else(|| json!(name)),
                "module": item.get("module").cloned().unwrap_or_default(),
                "ordinal": item.get("ordinal").cloned().unwrap_or(Value::Null),
            })
        },
    )
}

async fn export_resource(
    sessions: &SessionManager,
    database: &str,
    name: &str,
    uri: &str,
) -> Result<Value, McpError> {
    let exports = call_native(sessions, database, "exports", paginated_arguments(), uri).await?;
    Ok(export_entry(&exports, name))
}

fn export_entry(exports: &Value, name: &str) -> Value {
    let found = tool_list(exports, "exports")
        .iter()
        .enumerate()
        .find(|(_, item)| item.get("name").and_then(Value::as_str) == Some(name));
    found.map_or_else(
        || json!({"error": format!("Export not found: {name}")}),
        |(index, item)| {
            json!({
                "addr": item.get("address").cloned().unwrap_or(Value::Null),
                "name": item.get("name").cloned().unwrap_or_else(|| json!(name)),
                "ordinal": index + 1,
            })
        },
    )
}

async fn xrefs_from_resource(
    sessions: &SessionManager,
    database: &str,
    address: &str,
    uri: &str,
) -> Result<Value, McpError> {
    let address = resolve_address(sessions, database, address, uri).await?;
    let value = call_native(
        sessions,
        database,
        "xrefs_from",
        Map::from_iter([
            ("address".to_string(), json!(format!("{address:#x}"))),
            ("offset".to_string(), json!(0)),
            ("limit".to_string(), json!(RESOURCE_LIMIT)),
        ]),
        uri,
    )
    .await?;
    Ok(Value::Array(
        tool_list(&value, "xrefs_from")
            .iter()
            .map(|xref| {
                json!({
                    "addr": xref.get("to").cloned().unwrap_or(Value::Null),
                    "type": if xref
                        .get("is_code")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        "code"
                    } else {
                        "data"
                    },
                })
            })
            .collect(),
    ))
}

async fn resolve_address(
    sessions: &SessionManager,
    database: &str,
    value: &str,
    uri: &str,
) -> Result<u64, McpError> {
    if let Some(address) = parse_address(value) {
        return Ok(address);
    }
    let resolved = call_native(
        sessions,
        database,
        "resolve_function",
        Map::from_iter([("name".to_string(), json!(value))]),
        uri,
    )
    .await?;
    resolved
        .get("address")
        .and_then(address_number)
        .ok_or_else(|| {
            McpError::invalid_params(
                format!("Resource address '{value}' could not be resolved"),
                Some(json!({"uri": uri, "database": database})),
            )
        })
}

fn parse_address(value: &str) -> Option<u64> {
    crate::address::parse_address(value).ok()
}

fn address_number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_address))
}

fn json_response(uri: &str, value: Value) -> Result<ReadResourceResponse, McpError> {
    let text = serde_json::to_string(&value).map_err(|error| {
        McpError::internal_error(
            format!("Failed to serialize resource '{uri}': {error}"),
            Some(json!({"uri": uri})),
        )
    })?;
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type("application/json")
    ])
    .into())
}

fn resource_not_found(uri: &str) -> McpError {
    McpError::resource_not_found(
        format!("Unknown resource URI '{uri}'"),
        Some(json!({"uri": uri})),
    )
}

fn worker_error(database: &str, uri: &str, error: ToolError) -> McpError {
    McpError::internal_error(
        format!("Failed to read resource '{uri}': {error}"),
        Some(json!({"uri": uri, "database": database})),
    )
}

fn is_missing_struct(error: &ToolError) -> bool {
    match error {
        ToolError::InvalidParams(message) | ToolError::IdaError(message) => {
            message.contains("unknown struct name")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        export_entry, import_entry, metadata_resource, segments_resource, structs_resource,
        tool_list, types_resource, ResourceKind, ResourceRequest, RESOURCE_LIST_SOURCES,
    };
    use serde_json::json;

    #[test]
    fn parses_static_and_template_resources() {
        assert_eq!(
            ResourceRequest::parse("ida://idb/metadata").expect("metadata URI"),
            ResourceRequest {
                kind: ResourceKind::Metadata,
                database: None,
            }
        );
        assert_eq!(
            ResourceRequest::parse("ida://xrefs/from/0x401000").expect("xrefs URI"),
            ResourceRequest {
                kind: ResourceKind::XrefsFrom("0x401000".to_string()),
                database: None,
            }
        );
    }

    #[test]
    fn extracts_database_and_decodes_template_values() {
        assert_eq!(
            ResourceRequest::parse("ida://struct/My%20Type?database=session-1")
                .expect("scoped struct URI"),
            ResourceRequest {
                kind: ResourceKind::Struct("My Type".to_string()),
                database: Some("session-1".to_string()),
            }
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate_database_uris() {
        assert!(ResourceRequest::parse("file:///tmp/sample").is_err());
        assert!(ResourceRequest::parse("ida://unknown").is_err());
        assert!(ResourceRequest::parse("ida://types?database=one&database=two").is_err());
    }

    #[test]
    fn adapts_native_metadata_and_segments() {
        let metadata = metadata_resource(&json!({
            "input_file_path": "/tmp/sample.bin",
            "input_file_size": 32,
            "base_address": "0x1000",
            "min_address": "0x1000",
            "max_address": "0x1100",
            "md5": "abc",
            "sha256": "def",
            "processor": "x86",
            "bits": 64,
        }));
        assert_eq!(metadata["module"], "sample.bin");
        assert_eq!(metadata["size"], "0x100");
        assert_eq!(metadata["filesize"], "0x20");

        let segments = segments_resource(&json!([{
            "name": ".text",
            "start": "0x1000",
            "end": "0x1100",
            "size": 256,
            "permissions": "r-x",
        }]));
        assert_eq!(segments[0]["size"], "0x100");
        assert_eq!(segments[0]["permissions"], "r-x");
    }

    // ===================================================================
    // Root-shape adaptation.
    //
    // The tools this module reads do not agree on one root: the mandatory
    // `analysis_coverage` block puts `imports`/`exports` under an object while
    // `segments`/`entrypoints` answer with bare arrays. These pin both.
    // ===================================================================

    #[test]
    fn a_list_is_found_under_either_root() {
        let item = json!({"name": "printf"});
        let expected = std::slice::from_ref(&item);
        assert_eq!(tool_list(&json!([item.clone()]), "imports"), expected);
        assert_eq!(
            tool_list(
                &json!({"imports": [item.clone()], "analysis_coverage": {"complete": true}}),
                "imports"
            ),
            expected
        );
    }

    #[test]
    fn a_missing_or_renamed_list_reads_as_empty_rather_than_panicking() {
        assert!(tool_list(&json!({"analysis_coverage": {}}), "imports").is_empty());
        assert!(tool_list(&json!({"symbols": [{"name": "printf"}]}), "imports").is_empty());
        assert!(tool_list(&json!(null), "imports").is_empty());
    }

    #[test]
    fn the_source_table_carries_the_keys_that_differ_from_the_tool_name() {
        // These two are the reason the table exists at all; the rest happen to
        // match their tool name and the lookup would fall through correctly.
        assert_eq!(
            tool_list(&json!({"types": [{"name": "Elf64_Sym"}]}), "local_types").len(),
            1
        );
        assert_eq!(
            tool_list(&json!({"xrefs": [{"to": "0x1"}]}), "xrefs_from").len(),
            1
        );

        let mut sorted = RESOURCE_LIST_SOURCES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.as_slice(),
            RESOURCE_LIST_SOURCES,
            "keep the table sorted and free of duplicates so additions stay reviewable"
        );
    }

    #[test]
    fn an_import_is_found_under_the_object_root_the_tool_now_returns() {
        // The shape that bites: `imports` answers with an object, so reading
        // the root as an array searches nothing and every name is "not found".
        let answer = json!({
            "analysis_coverage": {"complete": true},
            "imports": [
                {"name": "__libc_start_main", "address": "0x4028", "module": "libc.so.6", "ordinal": 1},
            ],
        });
        let found = import_entry(&answer, "__libc_start_main");
        assert_eq!(found["name"], "__libc_start_main");
        assert_eq!(found["addr"], "0x4028");
        assert_eq!(found["module"], "libc.so.6");
        assert!(found.get("error").is_none());

        // A genuinely absent name still reports not found.
        assert!(import_entry(&answer, "nope").get("error").is_some());
        // And a bare-array root keeps working.
        assert_eq!(
            import_entry(&json!([{"name": "printf"}]), "printf")["name"],
            "printf"
        );
        // Ordinal lookup reaches into the object root too.
        assert_eq!(import_entry(&answer, "ord_1")["name"], "__libc_start_main");
    }

    #[test]
    fn an_export_is_found_under_the_object_root_the_tool_now_returns() {
        let answer = json!({
            "analysis_coverage": {"complete": true},
            "exports": [
                {"name": "_start", "address": "0x1040"},
                {"name": "main", "address": "0x118e"},
            ],
        });
        let found = export_entry(&answer, "main");
        assert_eq!(found["name"], "main");
        assert_eq!(found["addr"], "0x118e");
        assert_eq!(found["ordinal"], 2, "ordinal is the position in the list");
        assert!(found.get("error").is_none());

        assert!(export_entry(&answer, "nope").get("error").is_some());
        assert_eq!(
            export_entry(&json!([{"name": "main"}]), "main")["name"],
            "main"
        );
    }

    #[test]
    fn types_and_structs_read_their_object_roots() {
        let types = types_resource(&json!({
            "analysis_coverage": {"complete": true},
            "total": 1,
            "types": [{"ordinal": 1, "name": "Elf64_Sym", "decl": "struct Elf64_Sym {}"}],
        }));
        assert_eq!(types[0]["name"], "Elf64_Sym");

        let structs = structs_resource(&json!({
            "analysis_coverage": {"complete": true},
            "total": 1,
            "structs": [{"name": "Elf64_Sym", "size": 24, "is_union": false}],
        }));
        assert_eq!(structs[0]["name"], "Elf64_Sym");
        assert_eq!(structs[0]["size"], "0x18");
    }
}
