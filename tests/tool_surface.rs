//! Snapshot test for our own tool surface.
//!
//! The snapshot object is the surface this project implements — the native
//! `#[tool]` catalog, the supervisor's public catalog, and the resource URIs —
//! not a dump of the upstream `mrexodia/ida-pro-mcp` Python server. This
//! project does not claim contract-level compatibility with it.
//!
//! Schemas are intentionally not byte-pinned: they are generated from our own
//! request structs by schemars, so pinning them would only produce churn. What
//! matters is that names, counts, and the supervisor's `database` selector do
//! not change silently. Regenerate with:
//!
//! ```sh
//! UPDATE_TOOL_SURFACE_SNAPSHOT=1 cargo test --test tool_surface
//! ```

use ida_mcp::server::catalog;
use ida_mcp::supervisor::resource;
use ida_mcp::supervisor::server::{SESSION_TOOLS, UNSAFE_TOOLS};
use ida_mcp::supervisor::{supervisor_policy, SupervisorServer};
use serde_json::{json, Value};
use std::path::PathBuf;
use vibrev_kit::contract::{Audit, SurfaceReport};

/// Supervisor-implemented session tools that publish an `outputSchema`.
///
/// Not a ratchet. A name-per-tool list would say "all of them" the long way and
/// make every new tool an edit to it; `vibrev-kit`'s `OutputSchemas::Required`
/// says it in one word and covers a tool the day it lands. (`Staged(&[..])` is
/// there for a conversion that is genuinely mid-flight.)
///
/// What survives is the IDA-specific half: a session tool answers failure in the
/// payload rather than through `isError`, so its schema has to admit both arms —
/// something no other engine's surface does.
const SESSION_TOOLS_WITH_OUTPUT_SCHEMA: &[&str] =
    &["idb_close", "idb_list", "idb_open", "server_health"];

// Tools that must report how complete the analysis was.
//
// `open_idb` returns before auto-analysis settles. Every tool below answers
// with a count, a list or a nullable slot read out of an index the analyzer
// *writes*, so in that window it produces a well-formed, smaller, wrong answer
// that nothing else in the payload contradicts. Measured on a stock
// `/bin/cat`, before analysis settles versus after:
//
//   list_funcs.total          66 -> 161      idb_meta.function_count  66 -> 161
//   export_funcs.total        66 -> 161      list_globals.total      185 -> 298
//   exports                  251 -> 381      local_types.total         5 -> 26
//   structs.total              5 -> 12       find_insns.count        390 -> 409
//   xrefs_to(0xd2f8)           1 -> 2        find_insn_operands      175 -> 176
//   callers/callees/basic_blocks/callgraph/find_paths: error -> real data
//   addr_info(0x24a0).function  null -> main
//
// Excluded on purpose, all measured stable across the same transition:
// `segments`, `entrypoints`, `find_bytes`, `get_bytes`, `disasm` — loader-owned
// or byte-level, not analysis-owned. Also excluded: tools that fail *loudly*
// before analysis reaches them (`function_at`, `decompile`, `resolve_function`)
// and `read_struct`, which decodes bytes through a layout the caller named.
//
// A tool named here must publish `analysis_coverage` as a required property of
// its `outputSchema`. Never remove a name to make a test pass.
const TOOLS_WITH_ANALYSIS_COVERAGE: &[&str] = &[
    "addr_info",
    "analyze_component",
    "analyze_strings",
    "basic_blocks",
    "callees",
    "callers",
    "callgraph",
    "export_funcs",
    "exports",
    "find_insn_operands",
    "find_insns",
    "find_paths",
    "find_string",
    "func_profile",
    "idb_meta",
    "imports",
    "list_funcs",
    "list_functions",
    "list_globals",
    "local_types",
    "search",
    "search_structs",
    "strings",
    "structs",
    "survey_binary",
    "trace_data_flow",
    "xref_matrix",
    "xrefs_from",
    "xrefs_to",
    "xrefs_to_field",
    "xrefs_to_string",
];

fn snapshot_path() -> PathBuf {
    // The per-SDK manifests live in sdk/<version>/, the default manifest at the
    // repository root. Walk up until the snapshot directory shows up so the
    // same test runs from every manifest.
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("tests/snapshots/tool-surface.json");
        if candidate.exists() {
            return candidate;
        }
        assert!(dir.pop(), "tests/snapshots/tool-surface.json not found");
    }
}

fn names(tools: &[rmcp::model::Tool]) -> Vec<String> {
    tools.iter().map(|tool| tool.name.to_string()).collect()
}

fn actual_surface() -> Value {
    let safe = SupervisorServer::advertised_tools(false).expect("safe catalog");
    let unsafe_catalog = SupervisorServer::advertised_tools(true).expect("unsafe catalog");

    json!({
        "native_tools": catalog::native_tool_names().collect::<Vec<_>>(),
        "supervisor_tools": names(&safe),
        "supervisor_tools_unsafe_only": UNSAFE_TOOLS,
        "supervisor_session_tools": SESSION_TOOLS,
        "counts": {
            "native": catalog::native_tool_names().count(),
            "supervisor_safe": safe.len(),
            "supervisor_unsafe": unsafe_catalog.len(),
        },
    })
}

#[test]
fn tool_surface_matches_the_checked_in_snapshot() {
    let actual = actual_surface();
    let path = snapshot_path();

    if std::env::var_os("UPDATE_TOOL_SURFACE_SNAPSHOT").is_some() {
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&actual).expect("render snapshot")
        );
        std::fs::write(&path, rendered).expect("write snapshot");
        return;
    }

    let expected: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path:?}: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse {path:?}: {error}"));

    assert_eq!(
        actual, expected,
        "tool surface drifted from {path:?}; rerun with UPDATE_TOOL_SURFACE_SNAPSHOT=1 \
         after an intentional change"
    );
}

#[test]
fn supervisor_routes_every_native_tool_except_worker_local_lifecycle() {
    let advertised = names(&SupervisorServer::advertised_tools(true).expect("catalog"));

    for name in catalog::native_tool_names() {
        let routable = ida_mcp::supervisor::server::is_routable_tool(name);
        assert_eq!(
            routable,
            advertised.iter().any(|tool| tool == name),
            "{name}: routable and advertised must agree"
        );
    }
    // Worker-local database lifecycle stays behind the supervisor's own tools.
    for name in ["open_idb", "open_dsc", "close_idb"] {
        assert!(!ida_mcp::supervisor::server::is_routable_tool(name));
    }
}

#[test]
fn every_advertised_worker_tool_takes_a_database_selector() {
    for tool in SupervisorServer::advertised_tools(true).expect("catalog") {
        if SESSION_TOOLS.contains(&tool.name.as_ref()) {
            continue;
        }
        let required = tool.input_schema["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no required array", tool.name));
        assert!(
            required.iter().any(|item| item == "database"),
            "{} does not require a database selector",
            tool.name
        );
    }
}

#[test]
fn filters_narrow_the_supervisor_catalog() {
    let selection = |toolsets: &[&str], read_only: bool| vibrev_kit::policy::PolicyArgs {
        toolsets: toolsets.iter().map(|s| s.to_string()).collect(),
        read_only,
        ..Default::default()
    };

    let decompile = supervisor_policy(&selection(&["decompile"], false)).expect("decompile policy");
    let decompile_catalog = SupervisorServer::advertised_tools_with_filter(false, &decompile)
        .expect("filtered catalog");
    assert_eq!(
        names(&decompile_catalog),
        // The decompile category, plus the session tools it would otherwise have
        // no way to reach a database through.
        vec![
            "decompile".to_string(),
            "pseudocode_at".to_string(),
            "idb_open".to_string(),
            "idb_list".to_string(),
            "idb_close".to_string(),
            "server_health".to_string(),
        ]
    );

    let read_only = supervisor_policy(&selection(&[], true)).expect("read-only policy");
    let read_only_catalog = names(
        &SupervisorServer::advertised_tools_with_filter(false, &read_only)
            .expect("read-only catalog"),
    );
    for denied in ida_mcp::supervisor::tool_filter::read_only_deny_list_names() {
        assert!(
            !read_only_catalog.iter().any(|tool| tool == denied),
            "read-only leaked {denied}"
        );
    }
    for lifecycle in SESSION_TOOLS {
        assert!(
            read_only_catalog.iter().any(|tool| tool == lifecycle),
            "read-only removed {lifecycle}"
        );
    }
}

/// Duplicate names are `Rule::DuplicateName` in the shared contract; what stays
/// here is the lookup's other half — a name nobody registered resolves to
/// nothing rather than to whatever sorts nearby.
#[test]
fn an_unknown_name_resolves_to_no_native_tool() {
    assert!(catalog::native_tool_name("not_a_tool").is_none());
}

/// Both faces, checked against the cross-engine contract in `vibrev-kit`.
///
/// One call covers seven separate assertions: titles are
/// present and say something the name and description do not, annotations carry
/// an explicit `readOnlyHint`, every tool publishes an `outputSchema`, no `$ref`
/// dangles, no `$schema` dialect key leaks, no input schema publishes a numeric
/// `format` a strict consumer would refuse, the `analysis_coverage` block is
/// *required* where it is owed, and the catalog comes out in the same order
/// twice.
///
/// They moved because none of them was about IDA. Each engine carries its own
/// MCP face, and nothing forces consistency between engines; seven assertions
/// that only ever ran against this one were the shape that gap took. The
/// `uint*` one is the clearest case: this engine had
/// banned unsigned formats since before the scan existed, `bn-headless-mcp`
/// published them on every paged tool, and neither repository could see the
/// other's position. `bn-headless-mcp` now runs the same scan
/// (`src/surface.rs`), and the numbers are the argument: this engine reports 0
/// findings, that one reports 268, and every one of the 268 is a `$schema` leak
/// or an `anyOf: [T, null]` — the U2 divergence, which was previously something
/// a person had to notice by reading both repositories.
///
/// It is also the gate on kit itself. kit is a path dependency; once its modules
/// start landing in the request path, a kit change that breaks this engine has
/// nothing else in the build that would catch it before merge.
fn shared_contract() -> SurfaceReport {
    // Both faces, not the union: the supervisor rewrites schemas on its way out
    // (wrapping array roots, grafting `database`), and a wrapper that swallows
    // the `$defs` a `$ref` points at is invisible from the native side.
    let mut report = Audit::new("native")
        .require_output_property("analysis_coverage", TOOLS_WITH_ANALYSIS_COVERAGE)
        .run_repeated(catalog::native_tools);
    report.merge(
        Audit::new("supervisor")
            .require_output_property("analysis_coverage", TOOLS_WITH_ANALYSIS_COVERAGE)
            .run_repeated(|| SupervisorServer::advertised_tools(true).expect("supervisor catalog")),
    );
    report
}

#[test]
fn the_shared_tool_surface_contract_holds() {
    shared_contract().assert_clean();
}

/// A clean report over an empty catalog is the failure this test cannot afford,
/// so the scan says what it looked at and that gets checked too.
#[test]
fn the_scan_covered_both_catalogs() {
    let checked = shared_contract().checked();
    assert!(checked.tools > 150, "expected both faces, got {checked}");
    assert_eq!(checked.output_schemas, checked.tools);
    assert!(
        checked.refs > 100,
        "expected schemas with $ref, got {checked}"
    );
}

// ===========================================================================
// Advertised metadata: the IDA-specific half
// ===========================================================================

/// Session lifecycle annotations reflect what the tools actually do: opening
/// and closing a session mutate the supervisor's table, listing does not.
#[test]
fn session_tool_annotations_match_their_semantics() {
    let catalog = SupervisorServer::advertised_tools(true).expect("supervisor catalog");
    let annotations = |name: &str| {
        catalog
            .iter()
            .find(|tool| tool.name.as_ref() == name)
            .and_then(|tool| tool.annotations.clone())
            .unwrap_or_else(|| panic!("{name} has no annotations"))
    };

    assert_eq!(annotations("idb_open").read_only_hint, Some(false));
    assert_eq!(annotations("idb_open").destructive_hint, Some(false));
    assert_eq!(annotations("idb_list").read_only_hint, Some(true));
    assert_eq!(annotations("idb_close").read_only_hint, Some(false));
    assert_eq!(annotations("idb_close").destructive_hint, Some(true));
    assert_eq!(annotations("server_health").read_only_hint, Some(true));
    assert_eq!(annotations("server_health").destructive_hint, Some(false));
}

/// The supervisor's rewrite preserves the schema, and reshapes it the way it
/// says it does.
///
/// The kit checks that a schema is *there* on both faces. What it cannot know is
/// that this supervisor answers every routed call with a JSON object — an IDA
/// fact, and the reason `segments`' bare array has to move under a `result` key.
#[test]
fn the_supervisor_face_is_object_rooted_and_keeps_its_schemas() {
    let supervisor = SupervisorServer::advertised_tools(true).expect("supervisor catalog");

    let mut routed = 0usize;
    for name in catalog::native_tool_names() {
        let Some(tool) = supervisor.iter().find(|tool| tool.name.as_ref() == name) else {
            continue;
        };
        let schema = tool
            .output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{name} lost its outputSchema on the supervisor face"));
        assert_eq!(
            schema.get("type").and_then(Value::as_str),
            Some("object"),
            "{name}: the supervisor always answers with a JSON object"
        );
        routed += 1;
    }
    assert!(
        routed > 70,
        "expected most of the catalog to route, got {routed}"
    );

    // Session tools are the supervisor's own, and they report failure in the
    // payload rather than through `isError`, so their schema has to admit both.
    for name in SESSION_TOOLS_WITH_OUTPUT_SCHEMA {
        assert!(
            SESSION_TOOLS.contains(name),
            "SESSION_TOOLS_WITH_OUTPUT_SCHEMA names {name}, which is not a session tool"
        );
        let tool = supervisor
            .iter()
            .find(|tool| tool.name.as_ref() == *name)
            .unwrap_or_else(|| panic!("no session tool {name}"));
        let schema = tool
            .output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{name} lost its outputSchema"));
        assert!(
            schema.contains_key("anyOf"),
            "{name} must admit both the success and the {{error}} arm"
        );
    }
}

/// These four answer one shape, not array-or-object.
///
/// An `anyOf` or array root here would make the supervisor's `{result: ...}`
/// wrapper advertisement wrong for half the calls — which is why the shape has
/// to stay unified for them to publish a schema at all.
#[test]
fn the_reshaped_four_publish_an_object_rooted_results_schema() {
    for name in ["basic_blocks", "callees", "callers", "read_struct"] {
        let tool = catalog::native_tool(name).unwrap_or_else(|| panic!("no native tool {name}"));
        let schema = tool
            .output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{name} has no outputSchema"));
        assert_eq!(
            schema.get("type").and_then(Value::as_str),
            Some("object"),
            "{name} must publish an object root"
        );
        assert!(
            schema["properties"].get("results").is_some(),
            "{name} must publish `results`"
        );
        assert!(
            !schema.contains_key("anyOf"),
            "{name}: an anyOf root is what made this undescribable in the first place"
        );
    }
}

/// A bare-array worker payload is wrapped by `tool_result` before a client sees
/// it, so the supervisor must advertise the wrapped shape rather than the
/// worker's own. `segments` is the canonical example.
#[test]
fn the_supervisor_wraps_array_valued_output_schemas() {
    let native = catalog::native_tool("segments").expect("segments");
    assert_eq!(
        native
            .output_schema
            .as_ref()
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("array"),
        "the worker answers segments with a bare array"
    );

    let routed = SupervisorServer::advertised_tools(true)
        .expect("supervisor catalog")
        .into_iter()
        .find(|tool| tool.name.as_ref() == "segments")
        .expect("segments is routed");
    let schema = routed.output_schema.expect("segments outputSchema");
    assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
    assert_eq!(
        schema
            .get("properties")
            .and_then(|properties| properties.get("result"))
            .and_then(|result| result.get("type"))
            .and_then(Value::as_str),
        Some("array"),
        "the array moves under the `result` key the supervisor adds"
    );
}

/// The `resources/*` face reads lists out of `tools/*` answers, so a tool that
/// changes its root shape silently breaks a resource.
///
/// Every statistics tool carries an `analysis_coverage` block. `imports` and
/// `exports` have nowhere to put it on a bare array, so they use an object root
/// (`{imports|exports, analysis_coverage}`) while `segments` and `entrypoints`
/// stay arrays. Read the root with `as_array()` — which is `None` for an
/// object — and
/// `ida://import/<name>` and `ida://export/<name>` answered "not found" for
/// every name — including names the tools themselves had just returned. The
/// tool face was verified after that change; the resource face was not.
///
/// `RESOURCE_LIST_SOURCES` is the table `resource::tool_list` consults, so
/// checking it against the advertised `outputSchema` pins the two faces
/// together without needing IDA. A tool that moves its list to a new key, or
/// grows an object root without telling the resource layer, fails here.
#[test]
fn every_resource_list_source_matches_the_tool_it_reads() {
    // schemars writes an optional field as `type: ["array", "null"]`, so the
    // check has to admit both spellings. `xrefs_from.xrefs` is the one that
    // does: it is absent when several addresses were requested and the answer
    // arrives under `results` instead.
    fn admits(schema: &Value, wanted: &str) -> bool {
        match schema.get("type") {
            Some(Value::String(name)) => name == wanted,
            Some(Value::Array(names)) => names.iter().any(|name| name == wanted),
            _ => false,
        }
    }

    let mut object_rooted = 0usize;
    for (tool, key) in resource::RESOURCE_LIST_SOURCES {
        let native = catalog::native_tool(tool).unwrap_or_else(|| {
            panic!("RESOURCE_LIST_SOURCES names a tool that does not exist: {tool}")
        });
        let schema: Value = native
            .output_schema
            .as_ref()
            .map(|schema| Value::Object(schema.as_ref().clone()))
            .unwrap_or_else(|| {
                panic!("{tool} publishes no outputSchema to check the resource layer against")
            });

        // Bare-array root: `tool_list` takes it as-is and the key is unused.
        if admits(&schema, "array") {
            continue;
        }
        assert!(
            admits(&schema, "object"),
            "{tool} publishes a root that is neither an array nor an object: {:?}",
            schema.get("type")
        );
        object_rooted += 1;

        let property = schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(*key))
            .unwrap_or_else(|| {
                panic!(
                    "{tool} answers with an object but has no `{key}` property; \
                     supervisor::resource reads its list from there and would \
                     silently see an empty list, which is exactly how \
                     ida://import and ida://export broke"
                )
            });
        assert!(
            admits(property, "array"),
            "{tool}.{key} must be the list supervisor::resource iterates, got {:?}",
            property.get("type")
        );
    }

    assert!(
        object_rooted >= 5,
        "expected most of these tools to have an object root by now, got {object_rooted}; \
         if they all went back to bare arrays this check has stopped checking anything"
    );
}

/// The output cache must not change the advertised shape.
///
/// Replacing an oversized payload wholesale with a
/// `{truncated, preview, total_chars, output_id, download_url}` envelope would
/// force every schema to carry a second `anyOf` arm admitting it — and because
/// the cache is per-transport, that would make the published schema depend on
/// how the server was started.
///
/// `compact` now trims the payload in place (object keys all survive; only long
/// strings and long arrays are shortened) and moves the truncation bookkeeping
/// to `_meta.ida_mcp`, which no `outputSchema` describes. The envelope arm would
/// now advertise a value the server cannot produce, so it is gone, and one
/// catalog serves every transport.
///
/// The runtime half of this contract — that a truncated payload really does keep
/// its key set — is pinned by
/// `supervisor::server::tests::truncated_results_keep_the_original_structured_shape`.
#[test]
fn no_schema_advertises_the_retired_truncation_envelope() {
    let filter = vibrev_kit::policy::ToolPolicy::unrestricted();
    let tools = SupervisorServer::advertised_tools_with_filter(true, &filter).expect("catalog");

    let mut with_schema = 0usize;
    for tool in &tools {
        let Some(schema) = tool.output_schema.as_ref() else {
            continue;
        };
        with_schema += 1;
        let Some(arms) = schema.get("anyOf").and_then(Value::as_array) else {
            continue;
        };
        for arm in arms {
            let advertises_envelope = arm
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| {
                    properties.contains_key("truncated") && properties.contains_key("download_url")
                });
            assert!(
                !advertises_envelope,
                "{} advertises a truncation envelope the server does not produce",
                tool.name
            );
        }
    }
    assert!(
        with_schema >= 60,
        "expected most of the catalog to publish an outputSchema, got {with_schema}"
    );

    // `strings` is the canonical large-payload tool: its schema is the plain
    // native document, with no cache-conditional wrapper.
    let strings = tools
        .iter()
        .find(|tool| tool.name.as_ref() == "strings")
        .expect("strings");
    assert!(!strings
        .output_schema
        .as_ref()
        .expect("outputSchema")
        .contains_key("anyOf"));
}

// Dangling refs and `$schema` dialect leaks are checked by
// `Rule::DanglingRef` / `Rule::NonLocalRef` / `Rule::SchemaDialectLeak` inside
// `the_shared_tool_surface_contract_holds`. The kit walks `inputSchema` for
// dangling refs as well as `outputSchema`, so there is nothing left for a
// local version to add.
