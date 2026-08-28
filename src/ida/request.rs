//! Request types for the IDA worker.

use crate::error::ToolError;
use crate::ida::handlers::signature::SignatureRequest;
use crate::ida::int_spec::IntSpec;
use crate::ida::observability::ProgressSender;
use crate::ida::query::{
    DscDepsQuery, DscImageQuery, DscStringSearch, DscSymbolSearch, FunctionQuery, NameQuery,
    StringQuery, StringSearch, TypeQuery, XrefQuery,
};
use crate::ida::scan::{InsnScanRequest, ScanScope};
use crate::ida::types::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SdkMutation {
    Save {
        path: Option<String>,
    },
    DefineFunc {
        start: u64,
        end: Option<u64>,
    },
    DefineCode {
        address: u64,
    },
    Undefine {
        address: u64,
        size: u64,
    },
    Reanalyze {
        start: u64,
        end: u64,
    },
    MarkCfuncDirty {
        address: u64,
    },
    EnumUpsertMember {
        enum_name: String,
        member_name: String,
        value: u64,
        bitfield: bool,
    },
    RenameVariable {
        function_address: u64,
        old_name: String,
        new_name: String,
        stack: bool,
    },
    SurveyMetrics {
        function_addresses: Vec<u64>,
        string_addresses: Vec<u64>,
    },
    SignatureBytes {
        address: u64,
        size: usize,
        wildcard_operands: bool,
    },
    SetOperandType {
        address: u64,
        operand: i32,
        kind: String,
        target: Option<u64>,
        struct_name: Option<String>,
        delta: i64,
    },
    MakeData {
        address: u64,
        declaration: String,
        name: Option<String>,
        delete_existing: bool,
    },
}

/// Request types for the IDA worker
pub enum IdaRequest {
    Open {
        spec: OpenSpec,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        resp: oneshot::Sender<Result<OpenedDatabase, ToolError>>,
    },
    Warmup {
        build_caches: bool,
        init_hexrays: bool,
        resp: oneshot::Sender<Result<WarmupResult, ToolError>>,
    },
    Close {
        save: bool,
        resp: oneshot::Sender<()>,
    },
    CloseIfGeneration {
        generation: DatabaseGeneration,
        resp: oneshot::Sender<Result<ConditionalCloseResult, ToolError>>,
    },
    LoadDebugInfo {
        path: Option<String>,
        verbose: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalysisStatus {
        /// When set, the request is refused unless this database lifetime is
        /// still current, so a background task cannot observe the database
        /// that replaced the one it opened.
        expected_generation: Option<DatabaseGeneration>,
        resp: oneshot::Sender<Result<AnalysisStatus, ToolError>>,
    },
    DscLoadImage {
        module: String,
        /// See [`IdaRequest::AnalysisStatus::expected_generation`]. Loading an
        /// image mutates the database, so a stale task must be refused before
        /// it writes into a database it does not own.
        expected_generation: Option<DatabaseGeneration>,
        resp: oneshot::Sender<Result<DscImageInfo, ToolError>>,
    },
    DscLoadRegion {
        addr: u64,
        resp: oneshot::Sender<Result<DscRegionInfo, ToolError>>,
    },
    // The five below only read the dscu service, so none of them carries an
    // `expected_generation`: that guard exists to stop a stale task writing into
    // a database it no longer owns, and a query writes nothing.
    DscImages {
        query: DscImageQuery,
        resp: oneshot::Sender<Result<DscImageList, ToolError>>,
    },
    DscImageDeps {
        query: DscDepsQuery,
        resp: oneshot::Sender<Result<DscImageDeps, ToolError>>,
    },
    DscFindSymbols {
        search: DscSymbolSearch,
        resp: oneshot::Sender<Result<DscSymbolMatches, ToolError>>,
    },
    DscFindStrings {
        search: DscStringSearch,
        resp: oneshot::Sender<Result<DscStringMatches, ToolError>>,
    },
    DscRegionAt {
        addr: u64,
        resp: oneshot::Sender<Result<DscRegionQuery, ToolError>>,
    },
    ListFunctions {
        query: FunctionQuery,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    ResolveFunction {
        name: String,
        resp: oneshot::Sender<Result<FunctionInfo, ToolError>>,
    },
    DisasmByName {
        name: String,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Disasm {
        addr: u64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Decompile {
        addr: u64,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    Segments {
        resp: oneshot::Sender<Result<Vec<SegmentInfo>, ToolError>>,
    },
    Strings {
        query: StringQuery,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    LocalTypes {
        query: TypeQuery,
        resp: oneshot::Sender<Result<LocalTypeListResult, ToolError>>,
    },
    DeclareType {
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ApplyTypes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        stack_offset: Option<i64>,
        stack_name: Option<String>,
        decl: Option<String>,
        type_name: Option<String>,
        relaxed: bool,
        delay: bool,
        strict: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    InferTypes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<GuessTypeResult, ToolError>>,
    },
    AddrInfo {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<AddressInfo, ToolError>>,
    },
    FunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<FunctionRangeInfo, ToolError>>,
    },
    DisasmFunctionAt {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
        resp: oneshot::Sender<Result<String, ToolError>>,
    },
    DeclareStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    DeleteStack {
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
        resp: oneshot::Sender<Result<StackVarResult, ToolError>>,
    },
    StackFrame {
        addr: u64,
        resp: oneshot::Sender<Result<FrameInfo, ToolError>>,
    },
    Structs {
        query: TypeQuery,
        resp: oneshot::Sender<Result<StructListResult, ToolError>>,
    },
    StructInfo {
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructInfo, ToolError>>,
    },
    ReadStruct {
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
        resp: oneshot::Sender<Result<StructReadResult, ToolError>>,
    },
    XRefsTo {
        addr: u64,
        query: XrefQuery,
        resp: oneshot::Sender<Result<XRefListResult, ToolError>>,
    },
    XRefsFrom {
        addr: u64,
        query: XrefQuery,
        resp: oneshot::Sender<Result<XRefListResult, ToolError>>,
    },
    XRefsToField {
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
        resp: oneshot::Sender<Result<XrefsToFieldResult, ToolError>>,
    },
    Imports {
        query: NameQuery,
        resp: oneshot::Sender<Result<ImportListResult, ToolError>>,
    },
    Exports {
        query: NameQuery,
        resp: oneshot::Sender<Result<ExportListResult, ToolError>>,
    },
    Entrypoints {
        resp: oneshot::Sender<Result<Vec<String>, ToolError>>,
    },
    LuminaLookup {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    LuminaApply {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        force: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
        resp: oneshot::Sender<Result<BytesResult, ToolError>>,
    },
    AddBookmark {
        addr: u64,
        description: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SdkMutation {
        mutation: SdkMutation,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SetComments {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AppendComment {
        addr: u64,
        comment: String,
        scope: String,
        dedupe: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Rename {
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchBytes {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PatchAsm {
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    BasicBlocks {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<BasicBlockInfo>, ToolError>>,
    },
    Callees {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    Callers {
        addr: u64,
        resp: oneshot::Sender<Result<Vec<FunctionInfo>, ToolError>>,
    },
    IdbMeta {
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    LookupFunctions {
        queries: Vec<String>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ListGlobals {
        query: NameQuery,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    AnalyzeStrings {
        query: StringQuery,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindString {
        search: StringSearch,
        resp: oneshot::Sender<Result<StringListResult, ToolError>>,
    },
    XrefsToString {
        search: StringSearch,
        max_xrefs: usize,
        resp: oneshot::Sender<Result<StringXrefsResult, ToolError>>,
    },
    AnalyzeFuncs {
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindBytes {
        pattern: String,
        max_results: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchText {
        text: String,
        max_results: usize,
        scope: ScanScope,
        code_only: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    SearchImm {
        imm: u64,
        max_results: usize,
        scope: ScanScope,
        code_only: bool,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsns {
        scan: InsnScanRequest,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindInsnOperands {
        scan: InsnScanRequest,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    MakeSignature {
        request: SignatureRequest,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ReadInt {
        addr: u64,
        size: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetInt {
        addr: u64,
        spec: IntSpec,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    PutInt {
        addr: u64,
        spec: IntSpec,
        value: i128,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetString {
        addr: u64,
        max_len: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    GetGlobalValue {
        query: String,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    FindPaths {
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    CallGraph {
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    XrefMatrix {
        addrs: Vec<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    ExportFuncs {
        offset: usize,
        limit: usize,
        resp: oneshot::Sender<Result<FunctionListResult, ToolError>>,
    },
    PseudocodeAt {
        addr: u64,
        end_addr: Option<u64>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    RunScript {
        code: String,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
        resp: oneshot::Sender<Result<Value, ToolError>>,
    },
    Shutdown,
}

impl IdaRequest {
    pub fn progress_sender(&self) -> Option<&ProgressSender> {
        match self {
            IdaRequest::Open { progress_tx, .. }
            | IdaRequest::AnalyzeFuncs { progress_tx, .. }
            | IdaRequest::RunScript { progress_tx, .. } => progress_tx.as_ref(),
            _ => None,
        }
    }

    pub fn cancel_token(&self) -> Option<&CancellationToken> {
        match self {
            IdaRequest::Open { cancel, .. }
            | IdaRequest::AnalyzeFuncs { cancel, .. }
            | IdaRequest::RunScript { cancel, .. } => cancel.as_ref(),
            _ => None,
        }
    }
}
