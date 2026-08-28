use super::*;
use crate::ida::types as worker;
use serde_json::{json, Value};

/// Round-trip a worker value through its mirror and prove the two agree.
///
/// The mirrors carry `deny_unknown_fields`, so a field the worker emits and
/// the mirror lacks fails on deserialization; comparing the re-serialized
/// value to the original catches the opposite drift (a mirror field the
/// worker never emits, or one whose type changed).
fn assert_mirrors<Mirror>(worker_value: &impl serde::Serialize, label: &str)
where
    Mirror: serde::Serialize + serde::de::DeserializeOwned,
{
    let original = serde_json::to_value(worker_value)
        .unwrap_or_else(|error| panic!("{label}: serialize worker type: {error}"));
    let mirror: Mirror = serde_json::from_value(original.clone())
        .unwrap_or_else(|error| panic!("{label}: worker JSON does not fit the mirror: {error}"));
    let round_tripped = serde_json::to_value(&mirror)
        .unwrap_or_else(|error| panic!("{label}: serialize mirror: {error}"));

    assert_eq!(
        round_tripped, original,
        "{label}: mirror drifted from the worker type"
    );
}

/// A coverage block that is not the default of anything, so a mirror that
/// silently defaulted the field instead of reading it would be caught.
fn sample_coverage() -> AnalysisCoverage {
    AnalysisCoverage {
        complete: false,
        state: AnalysisCoverageState::Partial,
        analysis_running: true,
        engine_state: "AU_USED".to_string(),
        note: "sample".to_string(),
    }
}

/// [`assert_mirrors`] for a mirror whose tool splices `analysis_coverage`
/// into the worker payload on its way out.
///
/// The worker type does not carry the block and never will, so the guard
/// has to compare against worker JSON *plus* the same splice the tool does.
/// Drift detection is unchanged: any other added, removed or retyped field
/// still fails.
fn assert_mirrors_with_coverage<Mirror>(worker_value: &impl serde::Serialize, label: &str)
where
    Mirror: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut spliced = serde_json::to_value(worker_value)
        .unwrap_or_else(|error| panic!("{label}: serialize worker type: {error}"));
    spliced
        .as_object_mut()
        .unwrap_or_else(|| panic!("{label}: coverage only rides on object payloads"))
        .insert(
            ANALYSIS_COVERAGE_KEY.to_string(),
            sample_coverage().to_json(),
        );

    let mirror: Mirror = serde_json::from_value(spliced.clone()).unwrap_or_else(|error| {
        panic!("{label}: worker JSON plus coverage does not fit the mirror: {error}")
    });
    let round_tripped = serde_json::to_value(&mirror)
        .unwrap_or_else(|error| panic!("{label}: serialize mirror: {error}"));

    assert_eq!(
        round_tripped, spliced,
        "{label}: mirror drifted from the worker type"
    );
}

fn sample_segment() -> worker::SegmentInfo {
    worker::SegmentInfo {
        name: "__text".to_string(),
        start: "0x100000000".to_string(),
        end: "0x100001000".to_string(),
        size: 0x1000,
        permissions: "r-x".to_string(),
        r#type: "CODE".to_string(),
        bitness: 64,
    }
}

fn sample_function_range() -> worker::FunctionRangeInfo {
    worker::FunctionRangeInfo {
        address: "0x100000f00".to_string(),
        name: "main".to_string(),
        start: "0x100000f00".to_string(),
        end: "0x100000f40".to_string(),
        size: 0x40,
    }
}

fn sample_xref() -> worker::XRefInfo {
    worker::XRefInfo {
        from: "0x100000f10".to_string(),
        to: "0x100001000".to_string(),
        r#type: "Call_Near".to_string(),
        is_code: true,
        from_function: None,
    }
}

fn sample_struct_member() -> worker::StructMemberInfo {
    worker::StructMemberInfo {
        name: "field".to_string(),
        type_name: "int".to_string(),
        offset_bits: 32,
        size_bits: 32,
        offset: 4,
        size: 4,
        is_bitfield: false,
    }
}

fn sample_frame_range() -> worker::FrameRange {
    worker::FrameRange {
        start: "0x0".to_string(),
        end: "0x8".to_string(),
    }
}

#[test]
fn mirrors_match_the_worker_types() {
    assert_mirrors::<SegmentInfo>(&sample_segment(), "SegmentInfo");
    assert_mirrors::<FunctionRangeInfo>(&sample_function_range(), "FunctionRangeInfo");
    assert_mirrors::<XRefInfo>(&sample_xref(), "XRefInfo");
    assert_mirrors::<StructMemberInfo>(&sample_struct_member(), "StructMemberInfo");
    assert_mirrors::<FrameRange>(&sample_frame_range(), "FrameRange");
    assert_mirrors::<BasicBlockInfo>(
        &worker::BasicBlockInfo {
            start: "0x100000f00".to_string(),
            end: "0x100000f10".to_string(),
            size: 0x10,
            block_type: "ret".to_string(),
            successors: vec!["0x100000f20".to_string()],
            predecessors: vec!["0x100000ef0".to_string()],
        },
        "BasicBlockInfo",
    );

    assert_mirrors::<DebugInfoLoad>(
        &worker::DebugInfoLoad {
            path: "/tmp/sample.dSYM".to_string(),
            loaded: true,
            error: None,
        },
        "DebugInfoLoad",
    );
    assert_mirrors::<DscImageInfo>(
        &worker::DscImageInfo {
            index: 3,
            name: "/usr/lib/libobjc.A.dylib".to_string(),
            file_name: "libobjc.A.dylib".to_string(),
            address: "0x180000000".to_string(),
            address_value: 0x180000000,
            total_size: 0x10000,
            file_index: Some(1),
            loaded: true,
        },
        "DscImageInfo",
    );
    assert_mirrors::<DscRegionInfo>(
        &worker::DscRegionInfo {
            start: "0x180010000".to_string(),
            start_value: 0x180010000,
            size: 0x1000,
            kind: "data".to_string(),
            image_index: 3,
            name: "__DATA".to_string(),
            loaded: true,
        },
        "DscRegionInfo",
    );
    assert_mirrors::<StackVarResult>(
        &worker::StackVarResult {
            function: "0x100000f00".to_string(),
            name: "var_18".to_string(),
            offset: -0x18,
            code: 0,
            status: "ok".to_string(),
        },
        "StackVarResult",
    );
    assert_mirrors::<GuessTypeResult>(
        &worker::GuessTypeResult {
            address: "0x100002000".to_string(),
            code: 2,
            status: "ok".to_string(),
            decl: "char[16]".to_string(),
            kind: "array".to_string(),
        },
        "GuessTypeResult",
    );
    assert_mirrors::<BytesResult>(
        &worker::BytesResult {
            address: "0x100002000".to_string(),
            bytes: "deadbeef".to_string(),
            length: 4,
        },
        "BytesResult",
    );
    assert_mirrors::<GlobalInfo>(
        &worker::GlobalInfo {
            address: "0x100003000".to_string(),
            name: "g_flag".to_string(),
            is_public: true,
            is_weak: Some(false),
        },
        "GlobalInfo",
    );

    let function = worker::FunctionInfo {
        address: "0x100000f00".to_string(),
        name: "main".to_string(),
        size: 0x40,
    };
    assert_mirrors::<FunctionInfo>(&function, "FunctionInfo");
    assert_mirrors_with_coverage::<FunctionListResult>(
        &worker::FunctionListResult {
            functions: vec![function],
            total: 1,
            next_offset: Some(1),
        },
        "FunctionListResult",
    );

    assert_mirrors::<SymbolInfo>(
        &worker::SymbolInfo {
            name: "_main".to_string(),
            address: "0x100000f00".to_string(),
            delta: -4,
            exact: false,
            is_public: true,
            is_weak: false,
        },
        "SymbolInfo",
    );
    assert_mirrors_with_coverage::<AddressInfo>(
        &worker::AddressInfo {
            address: "0x100000f04".to_string(),
            segment: Some(sample_segment()),
            function: Some(sample_function_range()),
            symbol: Some(worker::SymbolInfo {
                name: "_main".to_string(),
                address: "0x100000f00".to_string(),
                delta: 4,
                exact: false,
                is_public: true,
                is_weak: false,
            }),
        },
        "AddressInfo",
    );

    let string = worker::StringInfo {
        address: "0x100002000".to_string(),
        content: "hello".to_string(),
        length: 5,
    };
    assert_mirrors::<StringInfo>(&string, "StringInfo");
    assert_mirrors_with_coverage::<StringListResult>(
        &worker::StringListResult {
            strings: vec![string],
            total: 1,
            next_offset: None,
        },
        "StringListResult",
    );

    let string_xref = worker::StringXrefInfo {
        address: "0x100002000".to_string(),
        content: "hello".to_string(),
        length: 5,
        xrefs: vec!["0x100000f20".to_string()],
        xref_count: 1,
    };
    assert_mirrors::<StringXrefInfo>(&string_xref, "StringXrefInfo");
    assert_mirrors_with_coverage::<StringXrefsResult>(
        &worker::StringXrefsResult {
            strings: vec![string_xref],
            total: 1,
            next_offset: Some(1),
        },
        "StringXrefsResult",
    );

    let local_type = worker::LocalTypeInfo {
        ordinal: 3,
        name: "Foo".to_string(),
        decl: "struct Foo { int a; };".to_string(),
        kind: "struct".to_string(),
    };
    assert_mirrors::<LocalTypeInfo>(&local_type, "LocalTypeInfo");
    assert_mirrors_with_coverage::<LocalTypeListResult>(
        &worker::LocalTypeListResult {
            types: vec![local_type],
            total: 1,
            next_offset: None,
        },
        "LocalTypeListResult",
    );

    let struct_summary = worker::StructSummary {
        ordinal: 3,
        name: "Foo".to_string(),
        size: 8,
        is_union: false,
        member_count: 1,
    };
    assert_mirrors::<StructSummary>(&struct_summary, "StructSummary");
    assert_mirrors_with_coverage::<StructListResult>(
        &worker::StructListResult {
            structs: vec![struct_summary],
            total: 1,
            next_offset: Some(1),
        },
        "StructListResult",
    );
    assert_mirrors::<StructInfo>(
        &worker::StructInfo {
            ordinal: 3,
            name: "Foo".to_string(),
            size: 8,
            is_union: false,
            member_count: 1,
            members: vec![sample_struct_member()],
        },
        "StructInfo",
    );

    let member_value = worker::StructMemberValue {
        name: "field".to_string(),
        type_name: "int".to_string(),
        offset_bits: 32,
        size_bits: 32,
        offset: 4,
        size: 4,
        is_bitfield: false,
        bytes: "01000000".to_string(),
    };
    assert_mirrors::<StructMemberValue>(&member_value, "StructMemberValue");
    assert_mirrors::<StructReadResult>(
        &worker::StructReadResult {
            address: "0x100003000".to_string(),
            ordinal: 3,
            name: "Foo".to_string(),
            size: 8,
            members: vec![member_value],
        },
        "StructReadResult",
    );

    let frame_member = worker::FrameMemberInfo {
        name: "var_8".to_string(),
        type_name: "int".to_string(),
        offset_bits: 0,
        size_bits: 32,
        offset: 0,
        size: 4,
        is_bitfield: false,
        part: "locals".to_string(),
    };
    assert_mirrors::<FrameMemberInfo>(&frame_member, "FrameMemberInfo");
    assert_mirrors::<FrameInfo>(
        &worker::FrameInfo {
            address: "0x100000f00".to_string(),
            frame_size: 0x20,
            ret_size: 8,
            frsize: 0x10,
            frregs: 8,
            argsize: 0,
            fpd: 0,
            args_range: sample_frame_range(),
            retaddr_range: sample_frame_range(),
            savregs_range: sample_frame_range(),
            locals_range: sample_frame_range(),
            member_count: 1,
            members: vec![frame_member],
        },
        "FrameInfo",
    );

    assert_mirrors::<XRefListResult>(
        &worker::XRefListResult {
            xrefs: vec![sample_xref()],
            truncated: true,
            next_offset: Some(1000),
        },
        "XRefListResult",
    );
    assert_mirrors_with_coverage::<XrefsToFieldResult>(
        &worker::XrefsToFieldResult {
            struct_ordinal: 3,
            struct_name: "Foo".to_string(),
            member_index: 0,
            member_name: "field".to_string(),
            member_type: "int".to_string(),
            member_offset_bits: 32,
            member_size_bits: 32,
            tid: "0xff00000000000010".to_string(),
            xrefs: vec![sample_xref()],
            truncated: false,
        },
        "XrefsToFieldResult",
    );

    assert_mirrors::<ImportInfo>(
        &worker::ImportInfo {
            address: "0x100004000".to_string(),
            name: "malloc".to_string(),
            module: "libSystem.B.dylib".to_string(),
            ordinal: 0,
        },
        "ImportInfo",
    );
    assert_mirrors::<ExportInfo>(
        &worker::ExportInfo {
            address: "0x100000f00".to_string(),
            name: "_main".to_string(),
            is_public: true,
        },
        "ExportInfo",
    );
}

/// `analysis_status` serializes the worker type and then splices
/// `session_id` in, so the mirror has to accept both shapes.
#[test]
fn analysis_status_mirror_accepts_both_faces() {
    let status = worker::AnalysisStatus {
        auto_enabled: true,
        auto_is_ok: true,
        auto_state: "idle".to_string(),
        auto_state_id: 0,
        analysis_running: false,
    };
    assert_mirrors::<AnalysisStatusOutput>(&status, "AnalysisStatus (worker face)");

    let mut with_session = serde_json::to_value(&status).expect("serialize");
    with_session
        .as_object_mut()
        .expect("object")
        .insert("session_id".to_string(), json!("sess-1"));
    let mirror: AnalysisStatusOutput =
        serde_json::from_value(with_session.clone()).expect("session_id must fit the mirror");
    assert_eq!(
        serde_json::to_value(&mirror).expect("serialize"),
        with_session
    );
}

/// Every optional-field union type must accept both arms it documents.
#[test]
fn union_outputs_accept_both_arms() {
    let single: DecompileOutput =
        serde_json::from_value(json!({"address": "0x1000", "code": "int main() {}"}))
            .expect("single-address decompile");
    assert!(single.results.is_none());

    let single: PseudocodeAtOutput = serde_json::from_value(json!({
        "function": {
            "address": "0x1000",
            "name": "main",
            "start": "0x1000",
            "end": "0x1100"
        },
        "query_address": "0x1010",
        "query_end_address": null,
        "eamap_ready": true,
        "statements": [],
        "count": 0
    }))
    .expect("single-address pseudocode_at");
    assert!(single.results.is_none());

    let batch: PseudocodeAtOutput = serde_json::from_value(json!({
        "results": [
            {"address": "0x1000", "pseudocode": {
                "function": {
                    "address": "0x1000",
                    "name": "main",
                    "start": "0x1000",
                    "end": "0x1100"
                },
                "query_address": "0x1000",
                "query_end_address": null,
                "eamap_ready": true,
                "statements": [],
                "count": 0
            }},
            {"address": "0x2000", "error": "no function"},
        ]
    }))
    .expect("multi-address pseudocode_at");
    assert_eq!(batch.results.map(|results| results.len()), Some(2));

    let started: OpenDscOutput = serde_json::from_value(json!({
        "status": "started",
        "task_id": "t1",
        "message": "DSC loading started in background."
    }))
    .expect("background open_dsc");
    assert!(started.path.is_none());

    let saved: SdkMutationOutput =
        serde_json::from_value(json!({"ok": true, "path": "/tmp/x.i64"}))
            .expect("sdk_mutation save");
    assert_eq!(saved.ok, Some(true));

    let batch: DecompileOutput = serde_json::from_value(json!({
        "results": [
            {"address": "0x1000", "decompile": "int main() {}"},
            {"address": "0x2000", "error": "no function"},
        ]
    }))
    .expect("multi-address decompile");
    assert_eq!(batch.results.map(|results| results.len()), Some(2));

    let single: DisasmOutput =
        serde_json::from_value(json!({"address": "0x1000", "disasm": "push rbp"}))
            .expect("single-address disasm");
    assert!(single.results.is_none());

    let batch: XRefsOutput = serde_json::from_value(json!({
        "results": [
            {"address": "0x1000", "xrefs": [], "truncated": false},
            {"address": "0x2000", "error": "bad address"},
        ],
        "analysis_coverage": sample_coverage().to_json(),
    }))
    .expect("multi-address xrefs");
    assert_eq!(batch.results.map(|results| results.len()), Some(2));

    let flat: XRefsOutput = serde_json::from_value(json!({
        "xrefs": [{"from": "0x1000", "to": "0x2000", "type": "Call_Near", "is_code": true}],
        "truncated": false,
        "analysis_coverage": sample_coverage().to_json(),
    }))
    .expect("single-address xrefs");
    assert!(flat.results.is_none());

    // The coverage block is not optional on either arm.
    let missing = serde_json::from_value::<XRefsOutput>(json!({
        "xrefs": [], "truncated": false,
    }));
    assert!(
        missing.is_err(),
        "an xrefs answer without analysis_coverage must not typecheck"
    );
}

/// [`AnalysisCoverage::to_json`] is hand-written so the splice cannot fail;
/// this is what keeps it honest against the derive.
#[test]
fn analysis_coverage_json_matches_serde() {
    for coverage in [
        AnalysisCoverage::from_ida(&worker::AnalysisStatus {
            auto_enabled: true,
            auto_is_ok: true,
            auto_state: "AU_NONE".to_string(),
            auto_state_id: 0,
            analysis_running: false,
        }),
        AnalysisCoverage::from_ida(&worker::AnalysisStatus {
            auto_enabled: true,
            auto_is_ok: false,
            auto_state: "AU_NONE".to_string(),
            auto_state_id: 0,
            analysis_running: true,
        }),
        AnalysisCoverage::unknown("worker is gone"),
    ] {
        assert_eq!(
            coverage.to_json(),
            serde_json::to_value(&coverage).expect("serialize coverage"),
            "to_json drifted from the derive"
        );
        // And it must round-trip, since the mirrors deserialize it.
        let parsed: AnalysisCoverage =
            serde_json::from_value(coverage.to_json()).expect("coverage round-trips");
        assert_eq!(parsed.complete, coverage.complete);
    }
}

/// The three states IDA can leave a database in, and what each must claim.
#[test]
fn ida_analysis_states_map_to_the_documented_coverage() {
    let status = |auto_is_ok, analysis_running| worker::AnalysisStatus {
        auto_enabled: true,
        auto_is_ok,
        // The real value a settled /bin/cat reports, which is exactly why
        // `auto_state` is diagnostics-only.
        auto_state: "AU_NONE".to_string(),
        auto_state_id: 0,
        analysis_running,
    };

    let settled = AnalysisCoverage::from_ida(&status(true, false));
    assert!(settled.complete);
    assert_eq!(settled.state, AnalysisCoverageState::Complete);

    let running = AnalysisCoverage::from_ida(&status(false, true));
    assert!(!running.complete);
    assert_eq!(running.state, AnalysisCoverageState::Partial);
    assert!(running.analysis_running);
    assert!(running.note.contains("analyze_funcs"));

    // Auto-analysis off and unfinished: nothing will improve on its own.
    let stalled = AnalysisCoverage::from_ida(&status(false, false));
    assert!(!stalled.complete);
    assert_eq!(stalled.state, AnalysisCoverageState::Partial);
    assert!(!stalled.analysis_running);

    // "Could not ask" is never "finished".
    let unknown = AnalysisCoverage::unknown("no database open");
    assert!(!unknown.complete);
    assert_eq!(unknown.state, AnalysisCoverageState::Unknown);
    assert!(unknown.note.contains("no database open"));
}

/// The coverage block must be *required* in every schema that declares it.
///
/// `Option` + `skip_serializing_if` would let it vanish from exactly the
/// responses it exists to annotate, so this walks the generated schemas and
/// refuses the optional spelling.
#[test]
fn coverage_is_required_wherever_it_is_declared() {
    let schemas = [
        ("SurveyBinaryOutput", schema::<SurveyBinaryOutput>()),
        ("AnalyzeComponentOutput", schema::<AnalyzeComponentOutput>()),
        ("FunctionListResult", schema::<FunctionListResult>()),
        ("IdbMetaOutput", schema::<IdbMetaOutput>()),
        ("ImportListOutput", schema::<ImportListOutput>()),
        ("ExportListOutput", schema::<ExportListOutput>()),
        ("XRefsOutput", schema::<XRefsOutput>()),
        ("CallGraphOutput", schema::<CallGraphOutput>()),
        ("CallersOutput", schema::<CallersOutput>()),
        ("CalleesOutput", schema::<CalleesOutput>()),
        ("BasicBlocksOutput", schema::<BasicBlocksOutput>()),
        ("AddressInfo", schema::<AddressInfo>()),
        ("SearchOutput", schema::<SearchOutput>()),
        ("TraceDataFlowOutput", schema::<TraceDataFlowOutput>()),
        ("FuncProfileOutput", schema::<FuncProfileOutput>()),
    ];
    for (label, generated) in schemas {
        assert!(
            generated["properties"].get(ANALYSIS_COVERAGE_KEY).is_some(),
            "{label} does not declare {ANALYSIS_COVERAGE_KEY}"
        );
        let required = generated["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{label} has no required list"));
        assert!(
            required.iter().any(|name| name == ANALYSIS_COVERAGE_KEY),
            "{label} declares {ANALYSIS_COVERAGE_KEY} but does not require it"
        );
    }

    // read_struct deliberately has no coverage block; see ReadStructOutput.
    let read_struct = schema::<ReadStructOutput>();
    assert!(
        read_struct["properties"]
            .get(ANALYSIS_COVERAGE_KEY)
            .is_none(),
        "read_struct grew a coverage block without a reason being written down"
    );
}

/// The four reshaped tools answer with one object shape, always.
#[test]
fn the_reshaped_four_are_object_rooted_with_results() {
    for (label, generated) in [
        ("BasicBlocksOutput", schema::<BasicBlocksOutput>()),
        ("CalleesOutput", schema::<CalleesOutput>()),
        ("CallersOutput", schema::<CallersOutput>()),
        ("ReadStructOutput", schema::<ReadStructOutput>()),
    ] {
        assert_eq!(
            generated.get("type").and_then(Value::as_str),
            Some("object"),
            "{label} must publish an object root, or the supervisor will \
                 advertise its {{result}} wrapper for it"
        );
        assert!(
            generated["properties"].get("results").is_some(),
            "{label} must publish `results`"
        );
    }

    // The per-address key names are the wire contract, so they must not be
    // renamed.
    let entry: BasicBlocksEntry = serde_json::from_value(json!({
        "address": "0x1000",
        "basic_blocks": [],
    }))
    .expect("entry keeps its documented key");
    assert!(entry.error.is_none());
    let entry: ReadStructEntry = serde_json::from_value(json!({
        "address": "0x1000",
        "struct": {
            "address": "0x1000", "ordinal": 3, "name": "Foo",
            "size": 8, "members": [],
        },
    }))
    .expect("read_struct entry keeps the `struct` key");
    assert!(entry.struct_value.is_some());
}

/// The published schemas must be usable by a client: object-rooted where we
/// return an object, array-rooted where we return a bare list.
#[test]
fn published_schemas_have_the_documented_root_type() {
    for (label, generated) in [
        ("FunctionListResult", schema::<FunctionListResult>()),
        ("DecompileOutput", schema::<DecompileOutput>()),
        ("ToolCatalogOutput", schema::<ToolCatalogOutput>()),
    ] {
        assert_eq!(
            generated.get("type").and_then(Value::as_str),
            Some("object"),
            "{label} must publish an object root"
        );
        assert!(
            generated.contains_key("properties"),
            "{label} must publish its properties"
        );
    }

    let segments = schema::<Vec<SegmentInfo>>();
    assert_eq!(segments.get("type").and_then(Value::as_str), Some("array"));
}
