//! IDA worker handle for async requests.

use crate::error::ToolError;
use crate::ida::handlers::signature::SignatureRequest;
use crate::ida::int_spec::IntSpec;
use crate::ida::observability::ProgressSender;
use crate::ida::query::{
    DscDepsQuery, DscImageQuery, DscStringSearch, DscSymbolSearch, FunctionQuery, NameQuery,
    StringQuery, StringSearch, TypeQuery, XrefQuery,
};
use crate::ida::request::{IdaRequest, SdkMutation};
use crate::ida::scan::{InsnScanRequest, ScanScope};
use crate::ida::types::*;
use serde_json::Value;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Default timeout for IDA operations (2 minutes)
const DEFAULT_TIMEOUT_SECS: u64 = 120;
/// Maximum allowed timeout (10 minutes)
pub const MAX_TIMEOUT_SECS: u64 = 600;
/// Maximum time to retry enqueuing close requests when the queue is full.
const CLOSE_SEND_TIMEOUT_SECS: u64 = 5;
/// Backoff between control enqueue retries (milliseconds).
const CONTROL_SEND_BACKOFF_MS: u64 = 25;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloseTokenLease {
    token: String,
    owner_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CloseTokenGrant {
    pub token: String,
    pub reused: bool,
    pub owner_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CloseAuthorization {
    Granted,
    GrantedByOverride { previous_owner_session_id: String },
    Denied { owner_session_id: String },
}

/// Internal state for close token ownership.
#[derive(Debug, Default)]
struct CloseTokenState {
    token: Mutex<Option<CloseTokenLease>>,
}

impl CloseTokenState {
    fn lock_token(&self) -> std::sync::MutexGuard<'_, Option<CloseTokenLease>> {
        match self.token.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn generate_token() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    fn issue_for_session(&self, session_id: &str) -> Result<CloseTokenGrant, String> {
        let mut guard = self.lock_token();
        if let Some(lease) = guard.as_ref() {
            if lease.owner_session_id == session_id {
                return Ok(CloseTokenGrant {
                    token: lease.token.clone(),
                    reused: true,
                    owner_session_id: lease.owner_session_id.clone(),
                });
            }
            return Err(lease.owner_session_id.clone());
        }

        let token = Self::generate_token();
        let lease = CloseTokenLease {
            token: token.clone(),
            owner_session_id: session_id.to_string(),
        };
        *guard = Some(lease.clone());
        Ok(CloseTokenGrant {
            token,
            reused: false,
            owner_session_id: lease.owner_session_id,
        })
    }

    fn authorize_close(
        &self,
        session_id: &str,
        token: Option<&str>,
        force: bool,
    ) -> CloseAuthorization {
        let guard = self.lock_token();
        let Some(lease) = guard.as_ref() else {
            return CloseAuthorization::Granted;
        };

        if token == Some(lease.token.as_str()) || lease.owner_session_id == session_id {
            CloseAuthorization::Granted
        } else if force {
            CloseAuthorization::GrantedByOverride {
                previous_owner_session_id: lease.owner_session_id.clone(),
            }
        } else {
            CloseAuthorization::Denied {
                owner_session_id: lease.owner_session_id.clone(),
            }
        }
    }

    fn clear(&self) {
        let mut guard = self.lock_token();
        *guard = None;
    }
}

/// Handle for sending requests to the main thread IDA worker
#[derive(Clone)]
pub struct IdaWorker {
    tx: mpsc::SyncSender<IdaRequest>,
    close_token: Arc<CloseTokenState>,
}

impl IdaWorker {
    /// Create a new worker handle with the given sender.
    pub fn new(tx: mpsc::SyncSender<IdaRequest>) -> Self {
        Self {
            tx,
            close_token: Arc::new(CloseTokenState::default()),
        }
    }

    pub(crate) fn issue_close_token_for_session(
        &self,
        session_id: &str,
    ) -> Result<CloseTokenGrant, String> {
        self.close_token.issue_for_session(session_id)
    }

    pub(crate) fn authorize_close(
        &self,
        session_id: &str,
        token: Option<&str>,
        force: bool,
    ) -> CloseAuthorization {
        self.close_token.authorize_close(session_id, token, force)
    }

    pub(crate) fn clear_close_token(&self) {
        self.close_token.clear();
    }

    fn try_send(&self, req: IdaRequest) -> Result<(), ToolError> {
        match self.tx.try_send(req) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => Err(ToolError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(ToolError::WorkerClosed),
        }
    }

    async fn send_with_retry(
        &self,
        req: IdaRequest,
        max_wait: Option<Duration>,
    ) -> Result<(), ToolError> {
        let start = Instant::now();
        let mut pending = req;
        loop {
            match self.tx.try_send(pending) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(req)) => {
                    if let Some(max_wait) = max_wait
                        && Instant::now().duration_since(start) >= max_wait
                    {
                        return Err(ToolError::Busy);
                    }
                    pending = req;
                    tokio::time::sleep(Duration::from_millis(CONTROL_SEND_BACKOFF_MS)).await;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return Err(ToolError::WorkerClosed),
            }
        }
    }

    /// Helper to receive with optional timeout
    async fn recv_with_timeout<T>(
        rx: oneshot::Receiver<Result<T, ToolError>>,
        timeout_secs: Option<u64>,
    ) -> Result<T, ToolError> {
        let timeout = Duration::from_secs(
            timeout_secs
                .unwrap_or(DEFAULT_TIMEOUT_SECS)
                .min(MAX_TIMEOUT_SECS),
        );
        match tokio::time::timeout(timeout, rx).await {
            Ok(result) => result?,
            Err(_) => Err(ToolError::Timeout(timeout.as_secs())),
        }
    }

    async fn recv<T>(rx: oneshot::Receiver<Result<T, ToolError>>) -> Result<T, ToolError> {
        rx.await?
    }

    /// Open an IDA database file and stream foreground progress updates.
    pub async fn open_observed(
        &self,
        spec: OpenSpec,
        timeout_secs: Option<u64>,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        self.open_observed_with_generation(spec, timeout_secs, progress_tx, cancel)
            .await
            .map(|opened| opened.info)
    }

    /// Open a database and retain its worker-local lifetime identity for
    /// generation-checked cleanup by background operations.
    pub(crate) async fn open_observed_with_generation(
        &self,
        spec: OpenSpec,
        _timeout_secs: Option<u64>,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<OpenedDatabase, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Open {
            spec,
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Rebuild string caches and/or initialize Hex-Rays on the open database.
    pub async fn warmup(
        &self,
        build_caches: bool,
        init_hexrays: bool,
    ) -> Result<WarmupResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Warmup {
            build_caches,
            init_hexrays,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Close the database only if it is still the lifetime opened by the
    /// caller. A mismatch is a successful no-op.
    pub(crate) async fn close_if_generation(
        &self,
        generation: DatabaseGeneration,
    ) -> Result<ConditionalCloseResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.send_with_retry(
            IdaRequest::CloseIfGeneration {
                generation,
                resp: tx,
            },
            Some(Duration::from_secs(CLOSE_SEND_TIMEOUT_SECS)),
        )
        .await?;
        let result = rx.await.map_err(|_| ToolError::WorkerClosed)??;
        if result == ConditionalCloseResult::Closed {
            self.clear_close_token();
        }
        Ok(result)
    }

    /// Close the currently open database.
    pub async fn close(&self) -> Result<(), ToolError> {
        self.close_with_save(true).await
    }

    /// Close the currently open database and control whether IDA writes it.
    pub async fn close_with_save(&self, save: bool) -> Result<(), ToolError> {
        let (tx, rx) = oneshot::channel();
        self.send_with_retry(
            IdaRequest::Close { save, resp: tx },
            Some(Duration::from_secs(CLOSE_SEND_TIMEOUT_SECS)),
        )
        .await?;
        rx.await.map_err(|_| ToolError::WorkerClosed)
    }

    pub async fn close_for_shutdown(&self) -> Result<(), ToolError> {
        let (tx, rx) = oneshot::channel();
        self.send_with_retry(
            IdaRequest::Close {
                save: true,
                resp: tx,
            },
            None,
        )
        .await?;
        rx.await.map_err(|_| ToolError::WorkerClosed)
    }

    /// Load external debug info (e.g., dSYM/DWARF) into the current database.
    pub async fn load_debug_info(
        &self,
        path: Option<String>,
        verbose: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LoadDebugInfo {
            path,
            verbose,
            resp: tx,
        })?;
        rx.await?
    }

    /// Report current auto-analysis status.
    pub async fn analysis_status(&self) -> Result<AnalysisStatus, ToolError> {
        self.analysis_status_for_generation(None).await
    }

    /// Report analysis status, optionally only while `expected_generation` is
    /// still the open database (see [`DatabaseGeneration`]).
    pub async fn analysis_status_for_generation(
        &self,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<AnalysisStatus, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalysisStatus {
            expected_generation,
            resp: tx,
        })?;
        rx.await?
    }

    /// Load a DSC image into the current database via IDA's native dscu service.
    pub async fn dsc_load_image(
        &self,
        module: &str,
        timeout_secs: Option<u64>,
    ) -> Result<DscImageInfo, ToolError> {
        self.dsc_load_image_for_generation(module, timeout_secs, None)
            .await
    }

    /// Load a DSC image, optionally only while `expected_generation` is still
    /// the open database (see [`DatabaseGeneration`]).
    pub async fn dsc_load_image_for_generation(
        &self,
        module: &str,
        timeout_secs: Option<u64>,
        expected_generation: Option<DatabaseGeneration>,
    ) -> Result<DscImageInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscLoadImage {
            module: module.to_string(),
            expected_generation,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Load a DSC region into the current database via IDA's native dscu service.
    pub async fn dsc_load_region(
        &self,
        addr: u64,
        timeout_secs: Option<u64>,
    ) -> Result<DscRegionInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscLoadRegion { addr, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// List the images in the open shared cache, with pagination.
    pub async fn dsc_images(
        &self,
        query: DscImageQuery,
        timeout_secs: Option<u64>,
    ) -> Result<DscImageList, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscImages { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Resolve an image's dependency closure.
    pub async fn dsc_image_deps(
        &self,
        query: DscDepsQuery,
        timeout_secs: Option<u64>,
    ) -> Result<DscImageDeps, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscImageDeps { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search the cache's symbol tables and image export tables.
    pub async fn dsc_find_symbols(
        &self,
        search: DscSymbolSearch,
        timeout_secs: Option<u64>,
    ) -> Result<DscSymbolMatches, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscFindSymbols { search, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search the cache's byte content for a string.
    pub async fn dsc_find_strings(
        &self,
        search: DscStringSearch,
        timeout_secs: Option<u64>,
    ) -> Result<DscStringMatches, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscFindStrings { search, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Resolve an address to its cache region without mapping anything.
    pub async fn dsc_region_at(
        &self,
        addr: u64,
        timeout_secs: Option<u64>,
    ) -> Result<DscRegionQuery, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DscRegionAt { addr, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Shutdown the IDA worker loop.
    pub async fn shutdown(&self) -> Result<(), ToolError> {
        self.send_with_retry(IdaRequest::Shutdown, None).await
    }

    /// List functions in the database with pagination.
    pub async fn list_functions(
        &self,
        query: FunctionQuery,
        timeout_secs: Option<u64>,
    ) -> Result<FunctionListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ListFunctions { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Resolve a function by name (exact or partial match).
    pub async fn resolve_function(&self, name: &str) -> Result<FunctionInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ResolveFunction {
            name: name.to_string(),
            resp: tx,
        })?;
        rx.await?
    }

    /// Disassemble a function by name (exact or partial match).
    pub async fn disasm_by_name(&self, name: &str, count: usize) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DisasmByName {
            name: name.to_string(),
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get disassembly at an address.
    pub async fn disasm(&self, addr: u64, count: usize) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Disasm {
            addr,
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Decompile a function using Hex-Rays.
    pub async fn decompile(&self, addr: u64) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Decompile { addr, resp: tx })?;
        rx.await?
    }

    /// List all segments.
    pub async fn segments(&self) -> Result<Vec<SegmentInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Segments { resp: tx })?;
        rx.await?
    }

    /// List strings with pagination and optional filter.
    pub async fn strings(
        &self,
        query: StringQuery,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Strings { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// List local types with pagination and optional filter.
    pub async fn local_types(
        &self,
        query: TypeQuery,
        timeout_secs: Option<u64>,
    ) -> Result<LocalTypeListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LocalTypes { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Declare a type (single or multi).
    pub async fn declare_type(
        &self,
        decl: String,
        relaxed: bool,
        replace: bool,
        multi: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeclareType {
            decl,
            relaxed,
            replace,
            multi,
            resp: tx,
        })?;
        rx.await?
    }

    /// Apply a type to an address.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_types(&self, spec: ApplyTypesSpec) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ApplyTypes {
            addr: spec.addr,
            name: spec.name,
            offset: spec.offset,
            stack_offset: spec.stack_offset,
            stack_name: spec.stack_name,
            decl: spec.decl,
            type_name: spec.type_name,
            relaxed: spec.relaxed,
            delay: spec.delay,
            strict: spec.strict,
            resp: tx,
        })?;
        rx.await?
    }

    /// Infer/guess a type for an address.
    pub async fn infer_types(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<GuessTypeResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::InferTypes {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get address context (segment, function, symbol).
    pub async fn addr_info(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<AddressInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AddrInfo {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get function containing an address.
    pub async fn function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
    ) -> Result<FunctionRangeInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FunctionAt {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        rx.await?
    }

    /// Disassemble the function containing an address.
    pub async fn disasm_function_at(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        count: usize,
    ) -> Result<String, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DisasmFunctionAt {
            addr,
            name,
            offset,
            count,
            resp: tx,
        })?;
        rx.await?
    }

    /// Declare a stack variable in a function frame.
    pub async fn declare_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        var_name: Option<String>,
        decl: String,
        relaxed: bool,
    ) -> Result<StackVarResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeclareStack {
            addr,
            name,
            offset,
            var_name,
            decl,
            relaxed,
            resp: tx,
        })?;
        rx.await?
    }

    /// Delete a stack variable from a function frame.
    pub async fn delete_stack(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: Option<i64>,
        var_name: Option<String>,
    ) -> Result<StackVarResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::DeleteStack {
            addr,
            name,
            offset,
            var_name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get stack frame info for a function at an address.
    pub async fn stack_frame(&self, addr: u64) -> Result<FrameInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::StackFrame { addr, resp: tx })?;
        rx.await?
    }

    /// List structs with pagination and optional filter.
    pub async fn structs(
        &self,
        query: TypeQuery,
        timeout_secs: Option<u64>,
    ) -> Result<StructListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Structs { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get struct info by ordinal or name.
    pub async fn struct_info(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructInfo, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::StructInfo {
            ordinal,
            name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Read a struct instance at an address.
    pub async fn read_struct(
        &self,
        addr: u64,
        ordinal: Option<u32>,
        name: Option<String>,
    ) -> Result<StructReadResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ReadStruct {
            addr,
            ordinal,
            name,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get cross-references to an address.
    pub async fn xrefs_to(
        &self,
        addr: u64,
        query: XrefQuery,
        timeout_secs: Option<u64>,
    ) -> Result<XRefListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsTo {
            addr,
            query,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get cross-references from an address.
    pub async fn xrefs_from(
        &self,
        addr: u64,
        query: XrefQuery,
        timeout_secs: Option<u64>,
    ) -> Result<XRefListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsFrom {
            addr,
            query,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get xrefs to a struct field.
    pub async fn xrefs_to_field(
        &self,
        ordinal: Option<u32>,
        name: Option<String>,
        member_index: Option<u32>,
        member_name: Option<String>,
        limit: usize,
    ) -> Result<XrefsToFieldResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XRefsToField {
            ordinal,
            name,
            member_index,
            member_name,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// List imports with pagination.
    pub async fn imports(&self, query: NameQuery) -> Result<ImportListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Imports { query, resp: tx })?;
        rx.await?
    }

    /// List exports with pagination.
    pub async fn exports(&self, query: NameQuery) -> Result<ExportListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Exports { query, resp: tx })?;
        rx.await?
    }

    /// Get entry points.
    pub async fn entrypoints(&self) -> Result<Vec<String>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Entrypoints { resp: tx })?;
        rx.await?
    }

    pub async fn lumina_lookup(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LuminaLookup {
            addr,
            name,
            offset,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    pub async fn lumina_apply(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        force: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LuminaApply {
            addr,
            name,
            offset,
            force,
            resp: tx,
        })?;
        // IDA's Lumina apply call is mutating and cannot be cancelled. Wait
        // for its truthful result instead of returning while it is still
        // changing the database on the IDA thread.
        Self::recv(rx).await
    }

    /// Read bytes from an address.
    pub async fn get_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        size: usize,
    ) -> Result<BytesResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetBytes {
            addr,
            name,
            offset,
            size,
            resp: tx,
        })?;
        rx.await?
    }

    /// Set a comment at an address.
    pub async fn set_comments(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        comment: String,
        repeatable: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SetComments {
            addr,
            name,
            offset,
            comment,
            repeatable,
            resp: tx,
        })?;
        rx.await?
    }

    /// Add or replace a bookmark at an address.
    pub async fn add_bookmark(&self, addr: u64, description: String) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AddBookmark {
            addr,
            description,
            resp: tx,
        })?;
        rx.await?
    }

    pub async fn sdk_mutation(&self, mutation: SdkMutation) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SdkMutation { mutation, resp: tx })?;
        rx.await?
    }

    /// Append a line or function comment.
    pub async fn append_comment(
        &self,
        addr: u64,
        comment: String,
        scope: String,
        dedupe: bool,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AppendComment {
            addr,
            comment,
            scope,
            dedupe,
            resp: tx,
        })?;
        rx.await?
    }

    /// Rename a symbol at an address.
    pub async fn rename(
        &self,
        addr: Option<u64>,
        current_name: Option<String>,
        new_name: String,
        flags: i32,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Rename {
            addr,
            current_name,
            new_name,
            flags,
            resp: tx,
        })?;
        rx.await?
    }

    /// Patch bytes at an address.
    pub async fn patch_bytes(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        bytes: Vec<u8>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PatchBytes {
            addr,
            name,
            offset,
            bytes,
            resp: tx,
        })?;
        rx.await?
    }

    /// Patch instructions with assembly text at an address.
    pub async fn patch_asm(
        &self,
        addr: Option<u64>,
        name: Option<String>,
        offset: i64,
        line: String,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PatchAsm {
            addr,
            name,
            offset,
            line,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get basic blocks for a function.
    pub async fn basic_blocks(&self, addr: u64) -> Result<Vec<BasicBlockInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::BasicBlocks { addr, resp: tx })?;
        rx.await?
    }

    /// Get functions called by a function.
    pub async fn callees(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Callees { addr, resp: tx })?;
        rx.await?
    }

    /// Get functions that call a function.
    pub async fn callers(&self, addr: u64) -> Result<Vec<FunctionInfo>, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::Callers { addr, resp: tx })?;
        rx.await?
    }

    /// Get IDB metadata.
    pub async fn idb_meta(&self) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::IdbMeta { resp: tx })?;
        rx.await?
    }

    /// Lookup functions by name or address (batch).
    pub async fn lookup_funcs(&self, queries: Vec<String>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::LookupFunctions { queries, resp: tx })?;
        rx.await?
    }

    /// List globals (named addresses outside functions).
    pub async fn list_globals(
        &self,
        query: NameQuery,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ListGlobals { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Analyze strings (with xrefs).
    pub async fn analyze_strings(
        &self,
        query: StringQuery,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeStrings { query, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find strings matching a query.
    pub async fn find_string(
        &self,
        search: StringSearch,
        timeout_secs: Option<u64>,
    ) -> Result<StringListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindString { search, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Get xrefs to strings matching a query.
    pub async fn xrefs_to_string(
        &self,
        search: StringSearch,
        max_xrefs: usize,
        timeout_secs: Option<u64>,
    ) -> Result<StringXrefsResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XrefsToString {
            search,
            max_xrefs,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run auto-analysis (functions) and wait for completion.
    pub async fn analyze_funcs(&self, timeout_secs: Option<u64>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeFuncs {
            progress_tx: None,
            cancel: None,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run auto-analysis (functions) and stream progress for foreground callers.
    pub async fn analyze_funcs_observed(
        &self,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::AnalyzeFuncs {
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Find byte pattern in the database.
    pub async fn find_bytes(
        &self,
        pattern: String,
        max_results: usize,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindBytes {
            pattern,
            max_results,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search text in the database.
    pub async fn search_text(
        &self,
        text: String,
        max_results: usize,
        scope: ScanScope,
        code_only: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SearchText {
            text,
            max_results,
            scope,
            code_only,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Search immediate values in the database, within a scope.
    pub async fn search_imm(
        &self,
        imm: u64,
        max_results: usize,
        scope: ScanScope,
        code_only: bool,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::SearchImm {
            imm,
            max_results,
            scope,
            code_only,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find instruction sequences by mnemonic patterns.
    pub async fn find_insns(
        &self,
        scan: InsnScanRequest,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindInsns { scan, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Find instruction operands by operand pattern, within a scan scope.
    pub async fn find_insn_operands(
        &self,
        scan: InsnScanRequest,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindInsnOperands { scan, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Build a byte signature for an address.
    pub async fn make_signature(
        &self,
        request: SignatureRequest,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::MakeSignature { request, resp: tx })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Read a typed integer (width, signedness and byte order) at an address.
    pub async fn get_int(&self, addr: u64, spec: IntSpec) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetInt {
            addr,
            spec,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, None).await
    }

    /// Write a typed integer at an address.
    pub async fn put_int(&self, addr: u64, spec: IntSpec, value: i128) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PutInt {
            addr,
            spec,
            value,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, None).await
    }

    /// Read integer value of size (1/2/4/8) at address.
    pub async fn read_int(&self, addr: u64, size: usize) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ReadInt {
            addr,
            size,
            resp: tx,
        })?;
        rx.await?
    }

    /// Read string at address.
    pub async fn get_string(&self, addr: u64, max_len: usize) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetString {
            addr,
            max_len,
            resp: tx,
        })?;
        rx.await?
    }

    /// Get value for a global (by name or address).
    pub async fn get_global_value(&self, query: String) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::GetGlobalValue { query, resp: tx })?;
        rx.await?
    }

    /// Find paths between addresses (CFG).
    pub async fn find_paths(
        &self,
        start: u64,
        end: u64,
        max_paths: usize,
        max_depth: usize,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::FindPaths {
            start,
            end,
            max_paths,
            max_depth,
            resp: tx,
        })?;
        rx.await?
    }

    /// Build a call graph rooted at a function address.
    pub async fn callgraph(
        &self,
        addr: u64,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::CallGraph {
            addr,
            max_depth,
            max_nodes,
            resp: tx,
        })?;
        rx.await?
    }

    /// Compute xref matrix for a set of addresses.
    pub async fn xref_matrix(&self, addrs: Vec<u64>) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::XrefMatrix { addrs, resp: tx })?;
        rx.await?
    }

    /// Export functions (paginated).
    pub async fn export_funcs(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<FunctionListResult, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::ExportFuncs {
            offset,
            limit,
            resp: tx,
        })?;
        rx.await?
    }

    /// Run a Python script via IDAPython in the open database.
    pub async fn run_script(
        &self,
        code: &str,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::RunScript {
            code: code.to_string(),
            progress_tx: None,
            cancel: None,
            resp: tx,
        })?;
        Self::recv_with_timeout(rx, timeout_secs).await
    }

    /// Run a Python script via IDAPython and stream progress for foreground callers.
    pub async fn run_script_observed(
        &self,
        code: &str,
        progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::RunScript {
            code: code.to_string(),
            progress_tx,
            cancel,
            resp: tx,
        })?;
        Self::recv(rx).await
    }

    /// Get decompiled pseudocode at a specific address or address range.
    /// If end_addr is provided, returns pseudocode for the range [addr, end_addr).
    /// Otherwise returns pseudocode for statements at the single address.
    pub async fn pseudocode_at(
        &self,
        addr: u64,
        end_addr: Option<u64>,
    ) -> Result<Value, ToolError> {
        let (tx, rx) = oneshot::channel();
        self.try_send(IdaRequest::PseudocodeAt {
            addr,
            end_addr,
            resp: tx,
        })?;
        rx.await?
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use serde_json::json;

    use crate::ida::request::IdaRequest;
    use crate::ida::worker::{CloseAuthorization, IdaWorker};
    use std::sync::mpsc;

    fn test_worker() -> IdaWorker {
        let (tx, _rx) = mpsc::sync_channel(1);
        IdaWorker::new(tx)
    }

    /// Wiring oracle: the generation a caller binds must reach the worker
    /// request, where the loop compares it. Without this, the `_for_generation`
    /// call sites could silently degrade to unbound and every other test would
    /// still pass.
    #[tokio::test]
    async fn bound_post_open_calls_carry_their_generation_to_the_worker() {
        use crate::ida::types::DatabaseGeneration;

        let (tx, rx) = mpsc::sync_channel(4);
        let worker = IdaWorker::new(tx);
        let generation = DatabaseGeneration(9);

        // The response senders are dropped with rx at the end of the test, so
        // these calls resolve as worker-closed; only the emitted request matters.
        let _ = tokio::time::timeout(
            Duration::from_millis(50),
            worker.dsc_load_image_for_generation("libobjc.A.dylib", Some(1), Some(generation)),
        )
        .await;
        match rx.recv().expect("dsc_load_image must reach the worker") {
            IdaRequest::DscLoadImage {
                expected_generation,
                ..
            } => assert_eq!(expected_generation, Some(generation)),
            _ => panic!("expected a DscLoadImage request"),
        }

        let _ = tokio::time::timeout(
            Duration::from_millis(50),
            worker.analysis_status_for_generation(Some(generation)),
        )
        .await;
        match rx.recv().expect("analysis_status must reach the worker") {
            IdaRequest::AnalysisStatus {
                expected_generation,
                ..
            } => assert_eq!(expected_generation, Some(generation)),
            _ => panic!("expected an AnalysisStatus request"),
        }

        // Foreground callers stay unbound and follow the current database.
        let _ = tokio::time::timeout(Duration::from_millis(50), worker.analysis_status()).await;
        match rx
            .recv()
            .expect("unbound analysis_status must reach the worker")
        {
            IdaRequest::AnalysisStatus {
                expected_generation,
                ..
            } => assert_eq!(expected_generation, None),
            _ => panic!("expected an AnalysisStatus request"),
        }
    }

    #[test]
    fn close_token_is_reused_for_same_session() {
        let worker = test_worker();
        let first = worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");
        let second = worker
            .issue_close_token_for_session("session-a")
            .expect("same session should reuse token");

        assert_eq!(first.token, second.token);
        assert!(!first.reused);
        assert!(second.reused);
    }

    #[test]
    fn close_tokens_are_fresh_uuid_v4_bearer_capabilities() {
        let worker = test_worker();
        let first = worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");
        worker.clear_close_token();
        let second = worker
            .issue_close_token_for_session("session-a")
            .expect("second issue should succeed");

        assert_ne!(first.token, second.token);
        for token in [&first.token, &second.token] {
            assert_eq!(token.len(), 32);
            assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
            let parsed = uuid::Uuid::parse_str(token).expect("token should parse as a UUID");
            assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
        }
    }

    #[test]
    fn close_token_is_denied_for_different_session() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        let denied = worker
            .issue_close_token_for_session("session-b")
            .expect_err("different session should be denied");
        assert_eq!(denied, "session-a");
    }

    #[test]
    fn owner_session_can_close_without_token() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-a", None, false),
            CloseAuthorization::Granted
        );
    }

    #[test]
    fn force_close_can_override_other_session() {
        let worker = test_worker();
        worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-b", None, true),
            CloseAuthorization::GrantedByOverride {
                previous_owner_session_id: "session-a".to_string(),
            }
        );
    }

    #[test]
    fn token_grants_close_from_any_session() {
        let worker = test_worker();
        let grant = worker
            .issue_close_token_for_session("session-a")
            .expect("first issue should succeed");

        assert_eq!(
            worker.authorize_close("session-b", Some(&grant.token), false),
            CloseAuthorization::Granted
        );
    }

    #[test]
    fn close_is_granted_when_no_lease_exists() {
        let worker = test_worker();
        assert_eq!(
            worker.authorize_close("session-x", None, false),
            CloseAuthorization::Granted
        );
    }

    /// A Lumina apply cannot be cancelled once IDA has sent it, so this call
    /// waits for the real answer rather than reporting a timeout the server
    /// could not act on. The tool still takes `timeout_secs`; it reaches the
    /// foreground operation guard, not this method.
    #[tokio::test]
    async fn lumina_apply_waits_for_a_truthful_result() {
        let (tx, rx) = mpsc::sync_channel(1);
        let worker = IdaWorker::new(tx);
        let responder = thread::spawn(move || {
            let request = rx.recv().expect("Lumina apply request should arrive");
            let IdaRequest::LuminaApply { resp, .. } = request else {
                panic!("expected Lumina apply request");
            };
            thread::sleep(Duration::from_millis(25));
            let _ = resp.send(Ok(json!({ "applied": true })));
        });

        let result = worker
            .lumina_apply(Some(0x401000), None, 0, false)
            .await
            .expect("non-cancellable apply should wait for the child");

        assert_eq!(result, json!({ "applied": true }));
        responder.join().expect("responder should finish");
    }
}
