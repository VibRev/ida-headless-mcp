use crate::error::ToolError;
use crate::ida::handlers::warmup::{BUILD_CACHES_STEP, INIT_HEXRAYS_STEP};
use crate::ida::leftover;
use crate::ida::pool::{PooledSessionState, WorkerPool};
use crate::ida::remote;
use crate::ida::types::{WarmupResult, WarmupStep};
use crate::server::catalog;
use rmcp::model::CallToolResult;
use rmcp::schemars::JsonSchema;
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::warn;

const DEFAULT_IDLE_TTL_SECS: u64 = 600;

fn native_worker_tool(name: &str) -> Option<&'static str> {
    catalog::native_tool_name(name)
}

#[derive(Debug, Clone)]
pub struct OpenSessionRequest {
    pub input_path: String,
    pub mode: String,
    pub run_auto_analysis: bool,
    pub build_caches: bool,
    pub init_hexrays: bool,
    pub idle_ttl_sec: u64,
    pub preferred_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SessionInfo {
    pub session_id: String,
    pub input_path: String,
    pub filename: String,
    pub created_at: String,
    pub last_accessed: String,
    pub is_analyzing: bool,
    pub metadata: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adopted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct OpenedSessionInfo {
    pub session_id: String,
    pub input_path: String,
    pub filename: String,
    pub created_at: String,
    pub last_accessed: String,
    pub is_analyzing: bool,
    pub metadata: Value,
}

struct ManagedSession {
    info: RwLock<SessionInfo>,
    canonical_path: PathBuf,
    worker: Arc<PooledSessionState>,
    idle_ttl_sec: u64,
    last_access: Mutex<Instant>,
    active_calls: AtomicUsize,
    /// Public tool name of the in-flight `call_native`. `std` so `server_health`
    /// can read it without joining the async `lifecycle` lock.
    current_call: std::sync::Mutex<Option<CurrentCall>>,
    lifecycle: Mutex<()>,
}

#[derive(Default)]
struct SessionMaps {
    by_id: HashMap<String, Arc<ManagedSession>>,
    by_path: HashMap<PathBuf, String>,
}

#[derive(Clone)]
pub struct SessionManager {
    pool: WorkerPool,
    sessions: Arc<RwLock<SessionMaps>>,
    open_lock: Arc<Mutex<()>>,
    reaper_started: Arc<AtomicBool>,
    reaper_cancel: CancellationToken,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct OpenSessionResult {
    pub success: bool,
    pub session: OpenedSessionInfo,
    pub warmup: Value,
    pub message: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CloseSessionResult {
    pub success: bool,
    pub session_id: String,
    pub backend: String,
    pub owned: bool,
    pub saved: Option<bool>,
    pub message: String,
}

/// `"ok"` when no native call is in flight, `"busy"` otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SessionHealthStatus {
    Ok,
    Busy,
}

/// Occupancy of one supervisor session. `busy_tool` / `busy_sec` are omitted
/// when `status` is `"ok"`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SessionHealth {
    pub status: SessionHealthStatus,
    pub session_id: String,
    pub input_path: String,
    pub filename: String,
    pub active_calls: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_sec: Option<f64>,
    pub backend: String,
    pub owned: bool,
    pub is_analyzing: bool,
}

/// `server_health` with no `database`: one snapshot per open session.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SessionHealthList {
    pub sessions: Vec<SessionHealth>,
    pub count: usize,
}

/// Wire shape of `server_health`: a single session, or every session.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ServerHealth {
    One(SessionHealth),
    All(SessionHealthList),
}

struct CurrentCall {
    tool: String,
    started: Instant,
}

impl From<&SessionInfo> for OpenedSessionInfo {
    fn from(info: &SessionInfo) -> Self {
        Self {
            session_id: info.session_id.clone(),
            input_path: info.input_path.clone(),
            filename: info.filename.clone(),
            created_at: info.created_at.clone(),
            last_accessed: info.last_accessed.clone(),
            is_analyzing: info.is_analyzing,
            metadata: info.metadata.clone(),
        }
    }
}

impl OpenSessionRequest {
    pub fn headless(input_path: String) -> Self {
        Self {
            input_path,
            mode: "prefer_headless".to_string(),
            run_auto_analysis: true,
            build_caches: true,
            init_hexrays: true,
            idle_ttl_sec: DEFAULT_IDLE_TTL_SECS,
            preferred_session_id: None,
        }
    }
}

impl SessionManager {
    pub fn new(pool: WorkerPool) -> Self {
        Self {
            pool,
            sessions: Arc::new(RwLock::new(SessionMaps::default())),
            open_lock: Arc::new(Mutex::new(())),
            reaper_started: Arc::new(AtomicBool::new(false)),
            reaper_cancel: CancellationToken::new(),
        }
    }

    pub fn start_idle_reaper(&self) {
        if self.reaper_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = manager.reaper_cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        manager.reap_idle().await;
                    }
                }
            }
        });
    }

    pub async fn open(
        &self,
        request: OpenSessionRequest,
        cancel: Option<CancellationToken>,
    ) -> Result<OpenSessionResult, ToolError> {
        ensure_not_cancelled(cancel.as_ref(), "idb_open")?;
        validate_mode(&request.mode)?;
        let _open_guard = if let Some(cancel) = cancel.as_ref() {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(cancelled_before_start("idb_open")),
                guard = self.open_lock.lock() => guard,
            }
        } else {
            self.open_lock.lock().await
        };
        ensure_not_cancelled(cancel.as_ref(), "idb_open")?;
        let canonical_path = canonical_input_path(&request.input_path)?;

        if let Some((existing_id, existing)) = self.find_by_path(&canonical_path).await {
            let _lifecycle_guard = if let Some(cancel) = cancel.as_ref() {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Err(cancelled_before_start("idb_open")),
                    guard = existing.lifecycle.lock() => guard,
                }
            } else {
                existing.lifecycle.lock().await
            };
            ensure_not_cancelled(cancel.as_ref(), "idb_open")?;
            if self.is_current(&existing_id, &existing).await {
                // Keep this check local: a worker RPC would hold `open_lock`
                // until the operation watchdog and block unrelated opens.
                if !existing.worker.has_live_database().await {
                    warn!(
                        session_id = %existing_id,
                        path = %canonical_path.display(),
                        reason = "worker transport is closed",
                        "discarding stale database session before reopening"
                    );
                    self.remove_if_current(&existing_id, &existing).await;
                    let _ = existing.worker.close_with_save(false).await;
                } else {
                    let info = touch(&existing).await;
                    return Ok(OpenSessionResult {
                        success: true,
                        message: format!(
                            "Binary already open: {} ({})",
                            info.filename, info.session_id
                        ),
                        session: OpenedSessionInfo::from(&info),
                        warmup: WarmupResult::reused().to_json(),
                    });
                }
            }
        }

        let session_id = requested_session_id(request.preferred_session_id.as_deref())?;
        {
            let sessions = self.sessions.read().await;
            if sessions.by_id.contains_key(&session_id) {
                return Err(ToolError::IdaError(format!(
                    "preferred session ID is already in use: {session_id}"
                )));
            }
        }

        let worker = Arc::new(PooledSessionState::new(
            self.pool.clone(),
            session_id.clone(),
        ));
        let leftover_preserve = leftover::existing_leftover_parts(&canonical_path);
        let opened = match worker
            .open_observed(
                crate::ida::OpenSpec {
                    path: canonical_path.to_string_lossy().into_owned(),
                    auto_analyse: request.run_auto_analysis,
                    ..Default::default()
                },
                Some(600),
                None,
                cancel,
            )
            .await
        {
            Ok(opened) => opened,
            Err(error) => {
                leftover::cleanup_leftover_parts(&canonical_path, &leftover_preserve);
                return Err(error);
            }
        };

        let worker_warmup =
            run_worker_warmup(&worker, request.build_caches, request.init_hexrays).await;
        let warmup = assemble_open_warmup(
            request.run_auto_analysis,
            opened.analysis_status.auto_is_ok,
            worker_warmup,
        );

        let timestamp = timestamp();
        let filename = canonical_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| canonical_path.display().to_string());
        let info = SessionInfo {
            session_id: session_id.clone(),
            input_path: canonical_path.display().to_string(),
            filename: filename.clone(),
            created_at: timestamp.clone(),
            last_accessed: timestamp,
            is_analyzing: !opened.analysis_status.auto_is_ok,
            metadata: serde_json::to_value(&opened).unwrap_or_else(|_| json!({})),
            is_active: Some(true),
            backend: Some("worker".to_string()),
            owned: Some(true),
            adopted: Some(false),
            busy: Some(false),
            pid: None,
            worker_pid: None,
        };
        let session = Arc::new(ManagedSession {
            info: RwLock::new(info.clone()),
            canonical_path: canonical_path.clone(),
            worker,
            idle_ttl_sec: request.idle_ttl_sec,
            last_access: Mutex::new(Instant::now()),
            active_calls: AtomicUsize::new(0),
            current_call: std::sync::Mutex::new(None),
            lifecycle: Mutex::new(()),
        });

        {
            let mut sessions = self.sessions.write().await;
            sessions.by_path.insert(canonical_path, session_id.clone());
            sessions.by_id.insert(session_id.clone(), session);
        }

        Ok(OpenSessionResult {
            success: true,
            session: OpenedSessionInfo::from(&info),
            warmup: warmup.to_json(),
            message: format!("Binary opened: {filename} ({session_id})"),
        })
    }

    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let values = sessions.by_id.values().cloned().collect::<Vec<_>>();
        drop(sessions);

        let mut result = Vec::with_capacity(values.len());
        for session in values {
            if !session.worker.has_live_database().await {
                let _lifecycle_guard = session.lifecycle.lock().await;
                if !session.worker.has_live_database().await {
                    let session_id = session.info.read().await.session_id.clone();
                    if self.remove_if_current(&session_id, &session).await {
                        let _ = session.worker.close_with_save(false).await;
                    }
                    continue;
                }
            }
            result.push(session.info.read().await.clone());
        }
        result.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        result
    }

    pub async fn close(&self, database: &str, save: bool) -> Result<CloseSessionResult, ToolError> {
        let session = self.get(database).await?;
        let _lifecycle_guard = session.lifecycle.lock().await;
        let session = {
            let mut sessions = self.sessions.write().await;
            let Some(current) = sessions.by_id.get(database) else {
                return Err(ToolError::IdaError(format!(
                    "Unknown database session '{database}'. Open a session with idb_open or enumerate with idb_list."
                )));
            };
            if !Arc::ptr_eq(current, &session) {
                return Err(ToolError::IdaError(format!(
                    "Database session '{database}' changed while closing"
                )));
            }
            let Some(session) = sessions.by_id.remove(database) else {
                return Err(ToolError::IdaError(format!(
                    "Unknown database session '{database}'. Open a session with idb_open or enumerate with idb_list."
                )));
            };
            sessions.by_path.remove(&session.canonical_path);
            session
        };

        let info = session.info.read().await.clone();
        session.worker.close_with_save(save).await?;
        Ok(CloseSessionResult {
            success: true,
            session_id: database.to_string(),
            backend: info.backend.unwrap_or_else(|| "worker".to_string()),
            owned: info.owned.unwrap_or(true),
            saved: save.then_some(true),
            message: format!("Session closed: {} ({database})", info.filename),
        })
    }

    pub async fn call(
        &self,
        database: &str,
        tool: &str,
        arguments: Map<String, Value>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        self.call_native(database, tool, arguments, cancel).await
    }

    pub async fn call_native(
        &self,
        database: &str,
        native_tool: &str,
        arguments: Map<String, Value>,
        cancel: Option<CancellationToken>,
    ) -> Result<Value, ToolError> {
        let result = self
            .call_native_result(database, native_tool, arguments, cancel)
            .await?;
        if let Some(err) = remote::result_error(&result, native_tool) {
            return Err(err);
        }
        if let Some(structured) = result.structured_content {
            return Ok(structured);
        }
        let text = remote::result_text(&result, native_tool)?;
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => Ok(value),
            Err(_) => Ok(Value::String(text)),
        }
    }

    pub async fn call_native_result(
        &self,
        database: &str,
        native_tool: &str,
        arguments: Map<String, Value>,
        cancel: Option<CancellationToken>,
    ) -> Result<CallToolResult, ToolError> {
        ensure_not_cancelled(cancel.as_ref(), native_tool)?;
        let session = self.get(database).await?;
        let _lifecycle_guard = if let Some(cancel) = cancel.as_ref() {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(cancelled_before_start(native_tool)),
                guard = session.lifecycle.lock() => guard,
            }
        } else {
            session.lifecycle.lock().await
        };
        ensure_not_cancelled(cancel.as_ref(), native_tool)?;
        // Recorded for `server_health`, which reads these without this lock.
        let active_call = session.begin_call(native_tool);
        *session.last_access.lock().await = Instant::now();
        let tool = native_worker_tool(native_tool).ok_or_else(|| {
            ToolError::IdaError(format!(
                "Native worker tool '{native_tool}' is not available"
            ))
        })?;
        let timeout_secs = arguments
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .or(Some(600));
        let result = session
            .worker
            .call_compat_result(tool, Value::Object(arguments), timeout_secs, cancel)
            .await;
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                drop(active_call);
                if !session.worker.has_live_database().await {
                    self.remove_if_current(database, &session).await;
                }
                return Err(error);
            }
        };
        drop(active_call);
        touch(&session).await;
        Ok(result)
    }

    /// Occupancy probe. Must not take `lifecycle` or talk to the worker: those
    /// are the exact waits this tool exists to observe rather than join.
    pub async fn health(&self, database: Option<&str>) -> Result<ServerHealth, ToolError> {
        if let Some(database) = database {
            let session = self.get(database).await?;
            return Ok(ServerHealth::One(session.health_snapshot().await));
        }

        let sessions = {
            let guard = self.sessions.read().await;
            guard.by_id.values().cloned().collect::<Vec<_>>()
        };
        let mut snapshots = Vec::with_capacity(sessions.len());
        for session in sessions {
            snapshots.push(session.health_snapshot().await);
        }
        snapshots.sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let count = snapshots.len();
        Ok(ServerHealth::All(SessionHealthList {
            sessions: snapshots,
            count,
        }))
    }

    pub async fn shutdown(&self) {
        self.reaper_cancel.cancel();
        let session_ids = {
            let sessions = self.sessions.read().await;
            sessions.by_id.keys().cloned().collect::<Vec<_>>()
        };
        for session_id in session_ids {
            let _ = self.close(&session_id, true).await;
        }
        self.pool.shutdown_all().await;
    }

    async fn reap_idle(&self) {
        let sessions = {
            let guard = self.sessions.read().await;
            guard.by_id.values().cloned().collect::<Vec<_>>()
        };
        let mut expired = Vec::new();
        for session in sessions {
            if session.idle_ttl_sec == 0 || session.active_calls.load(Ordering::Acquire) != 0 {
                continue;
            }
            if session.last_access.lock().await.elapsed()
                >= Duration::from_secs(session.idle_ttl_sec)
            {
                expired.push(session.info.read().await.session_id.clone());
            }
        }
        for session_id in expired {
            let _ = self.close(&session_id, true).await;
        }
    }

    async fn get(&self, database: &str) -> Result<Arc<ManagedSession>, ToolError> {
        self.sessions
            .read()
            .await
            .by_id
            .get(database)
            .cloned()
            .ok_or_else(|| {
                ToolError::IdaError(format!(
                    "Unknown database session '{database}'. Open a session with idb_open or enumerate with idb_list."
                ))
            })
    }

    async fn is_current(&self, database: &str, session: &Arc<ManagedSession>) -> bool {
        self.sessions
            .read()
            .await
            .by_id
            .get(database)
            .is_some_and(|current| Arc::ptr_eq(current, session))
    }

    async fn remove_if_current(&self, database: &str, session: &Arc<ManagedSession>) -> bool {
        let mut sessions = self.sessions.write().await;
        if !sessions
            .by_id
            .get(database)
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            return false;
        }
        sessions.by_id.remove(database);
        if sessions
            .by_path
            .get(&session.canonical_path)
            .is_some_and(|current| current == database)
        {
            sessions.by_path.remove(&session.canonical_path);
        }
        true
    }

    async fn find_by_path(&self, canonical_path: &Path) -> Option<(String, Arc<ManagedSession>)> {
        let sessions = self.sessions.read().await;
        let session_id = sessions.by_path.get(canonical_path)?.clone();
        sessions
            .by_id
            .get(&session_id)
            .cloned()
            .map(|session| (session_id, session))
    }
}

fn canonical_input_path(input_path: &str) -> Result<PathBuf, ToolError> {
    let trimmed = input_path.trim();
    if trimmed.is_empty() {
        return Err(ToolError::InvalidPath(input_path.to_string()));
    }
    #[cfg(windows)]
    let canonical = {
        // std::fs::canonicalize emits `\\?\` paths on Windows, which IDA rejects.
        // `dunce` keeps canonicalization while using legacy syntax whenever safe.
        dunce::canonicalize(trimmed)
    };
    #[cfg(not(windows))]
    let canonical = std::fs::canonicalize(trimmed);

    canonical.map_err(|error| ToolError::InvalidPath(format!("{trimmed}: {error}")))
}

fn validate_mode(mode: &str) -> Result<(), ToolError> {
    match mode {
        "prefer_headless" | "force_headless" | "prefer_gui" => Ok(()),
        "force_gui" => Err(ToolError::IdaError(
            "force_gui is unavailable in the headless-only Rust server".to_string(),
        )),
        other => Err(ToolError::IdaError(format!(
            "Invalid idb_open mode '{other}'; expected prefer_headless, force_headless, prefer_gui, or force_gui"
        ))),
    }
}

fn requested_session_id(preferred: Option<&str>) -> Result<String, ToolError> {
    let Some(preferred) = preferred.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(uuid::Uuid::new_v4().simple().to_string());
    };
    if preferred.len() > 128
        || !preferred
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    {
        return Err(ToolError::IdaError(
            "preferred_session_id must be 1-128 ASCII letters, digits, '-', '_', or '.'"
                .to_string(),
        ));
    }
    Ok(preferred.to_string())
}

fn cancelled_before_start(operation: &str) -> ToolError {
    ToolError::Cancelled(format!("cancelled {operation} before it started"))
}

fn ensure_not_cancelled(
    cancel: Option<&CancellationToken>,
    operation: &str,
) -> Result<(), ToolError> {
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        Err(cancelled_before_start(operation))
    } else {
        Ok(())
    }
}

async fn touch(session: &ManagedSession) -> SessionInfo {
    *session.last_access.lock().await = Instant::now();
    let mut info = session.info.write().await;
    info.last_accessed = timestamp();
    info.clone()
}

impl ManagedSession {
    fn begin_call(&self, tool: &str) -> ActiveCall<'_> {
        *self.current_call_lock() = Some(CurrentCall {
            tool: tool.to_string(),
            started: Instant::now(),
        });
        self.active_calls.fetch_add(1, Ordering::AcqRel);
        ActiveCall { session: self }
    }

    fn current_call_lock(&self) -> std::sync::MutexGuard<'_, Option<CurrentCall>> {
        self.current_call
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn health_snapshot(&self) -> SessionHealth {
        let info = self.info.read().await;
        let active_calls = self.active_calls.load(Ordering::Acquire);
        let current = self.current_call_lock();
        snapshot_health(&info, active_calls, current.as_ref())
    }
}

fn snapshot_health(
    info: &SessionInfo,
    active_calls: usize,
    current: Option<&CurrentCall>,
) -> SessionHealth {
    let (status, busy_tool, busy_sec) = if active_calls > 0 {
        (
            SessionHealthStatus::Busy,
            current.map(|call| call.tool.clone()),
            current.map(|call| call.started.elapsed().as_secs_f64()),
        )
    } else {
        (SessionHealthStatus::Ok, None, None)
    };
    SessionHealth {
        status,
        session_id: info.session_id.clone(),
        input_path: info.input_path.clone(),
        filename: info.filename.clone(),
        active_calls,
        busy_tool,
        busy_sec,
        backend: info.backend.clone().unwrap_or_else(|| "worker".to_string()),
        owned: info.owned.unwrap_or(true),
        // Cached on `info` at open (and whatever later writes it). Do not
        // refresh via a worker RPC — that would queue behind the busy tool.
        is_analyzing: info.is_analyzing,
    }
}

struct ActiveCall<'a> {
    session: &'a ManagedSession,
}

impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.session.active_calls.fetch_sub(1, Ordering::AcqRel);
        *self.session.current_call_lock() = None;
    }
}

fn timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

async fn run_worker_warmup(
    worker: &PooledSessionState,
    build_caches: bool,
    init_hexrays: bool,
) -> WarmupResult {
    if !build_caches && !init_hexrays {
        return WarmupResult::from_steps(Vec::new());
    }
    match worker.warmup(build_caches, init_hexrays).await {
        Ok(result) => result,
        Err(error) => warmup_rpc_failure(build_caches, init_hexrays, &error),
    }
}

fn warmup_rpc_failure(build_caches: bool, init_hexrays: bool, error: &ToolError) -> WarmupResult {
    let mut steps = Vec::new();
    if build_caches {
        steps.push(WarmupStep::err(BUILD_CACHES_STEP, 0, error.to_string()));
    }
    if init_hexrays {
        steps.push(WarmupStep::err(INIT_HEXRAYS_STEP, 0, error.to_string()));
    }
    WarmupResult::from_steps(steps)
}

fn assemble_open_warmup(
    run_auto_analysis: bool,
    auto_is_ok: bool,
    worker: WarmupResult,
) -> WarmupResult {
    let mut steps = Vec::new();
    if run_auto_analysis {
        steps.push(WarmupStep {
            step: "auto_wait".to_string(),
            ok: auto_is_ok,
            ms: 0,
            error: None,
        });
    }
    steps.extend(worker.steps);
    WarmupResult::from_steps(steps)
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::canonical_input_path;
    use super::{
        assemble_open_warmup, native_worker_tool, requested_session_id, snapshot_health,
        validate_mode, warmup_rpc_failure, CurrentCall, ServerHealth, SessionHealthStatus,
        SessionInfo, SessionManager,
    };
    use crate::error::ToolError;
    use crate::ida::handlers::warmup::{BUILD_CACHES_STEP, INIT_HEXRAYS_STEP};
    use crate::ida::pool::{WorkerPool, WorkerPoolConfig};
    use crate::ida::types::{WarmupResult, WarmupStep};
    use serde_json::{json, Value};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    fn test_pool() -> WorkerPool {
        WorkerPool::new(WorkerPoolConfig {
            max_workers: 1,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(600),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        })
    }

    fn test_info() -> SessionInfo {
        SessionInfo {
            session_id: "sess-1".to_string(),
            input_path: "/tmp/fixture.bin".to_string(),
            filename: "fixture.bin".to_string(),
            created_at: "0".to_string(),
            last_accessed: "0".to_string(),
            is_analyzing: false,
            metadata: json!({}),
            is_active: Some(true),
            backend: Some("worker".to_string()),
            owned: Some(true),
            adopted: Some(false),
            busy: Some(false),
            pid: None,
            worker_pid: None,
        }
    }

    impl SessionManager {
        async fn insert_test_session(
            &self,
            session_id: &str,
        ) -> std::sync::Arc<super::ManagedSession> {
            let info = test_info();
            let session = std::sync::Arc::new(super::ManagedSession {
                info: tokio::sync::RwLock::new(SessionInfo {
                    session_id: session_id.to_string(),
                    ..info
                }),
                canonical_path: PathBuf::from("/tmp/fixture.bin"),
                worker: std::sync::Arc::new(crate::ida::pool::PooledSessionState::new(
                    self.pool.clone(),
                    session_id.to_string(),
                )),
                idle_ttl_sec: 0,
                last_access: tokio::sync::Mutex::new(Instant::now()),
                active_calls: std::sync::atomic::AtomicUsize::new(0),
                current_call: std::sync::Mutex::new(None),
                lifecycle: tokio::sync::Mutex::new(()),
            });
            let mut sessions = self.sessions.write().await;
            sessions
                .by_id
                .insert(session_id.to_string(), session.clone());
            session
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_path_uses_ida_compatible_windows_syntax() {
        let executable = std::env::current_exe().expect("current executable path");
        let canonical = canonical_input_path(executable.to_string_lossy().as_ref())
            .expect("canonical executable path");

        assert!(
            !canonical.to_string_lossy().starts_with(r"\\?\"),
            "ordinary Windows paths passed to IDA must not use verbatim syntax"
        );
    }

    #[test]
    fn resolves_public_and_internal_worker_tools() {
        assert_eq!(native_worker_tool("list_funcs"), Some("list_funcs"));
        assert_eq!(native_worker_tool("bookmark_add"), Some("bookmark_add"));
        assert_eq!(native_worker_tool("comment_append"), Some("comment_append"));
        assert_eq!(native_worker_tool("sdk_mutation"), Some("sdk_mutation"));
        assert_eq!(native_worker_tool("not_a_tool"), None);
    }

    #[test]
    fn validates_headless_modes() {
        assert!(validate_mode("prefer_headless").is_ok());
        assert!(validate_mode("force_headless").is_ok());
        assert!(validate_mode("prefer_gui").is_ok());
        assert!(validate_mode("force_gui").is_err());
        assert!(validate_mode("other").is_err());
    }

    #[test]
    fn validates_preferred_session_ids() {
        assert_eq!(
            requested_session_id(Some("sample-1")).expect("valid ID"),
            "sample-1"
        );
        assert!(requested_session_id(Some("../bad")).is_err());
        assert!(requested_session_id(Some("contains space")).is_err());
    }

    #[test]
    fn idle_snapshot_omits_busy_fields() {
        let health = snapshot_health(&test_info(), 0, None);
        assert_eq!(health.status, SessionHealthStatus::Ok);
        assert_eq!(health.active_calls, 0);
        assert!(health.busy_tool.is_none());
        assert!(health.busy_sec.is_none());
        assert!(!health.is_analyzing);
    }

    #[test]
    fn busy_snapshot_includes_the_inflight_tool() {
        let current = CurrentCall {
            tool: "decompile".to_string(),
            started: Instant::now() - Duration::from_secs(2),
        };
        let health = snapshot_health(&test_info(), 1, Some(&current));
        assert_eq!(health.status, SessionHealthStatus::Busy);
        assert_eq!(health.active_calls, 1);
        assert_eq!(health.busy_tool.as_deref(), Some("decompile"));
        assert!(health.busy_sec.is_some_and(|secs| secs >= 2.0));
    }

    #[tokio::test]
    async fn health_unknown_database_is_an_error() {
        let manager = SessionManager::new(test_pool());
        let error = manager
            .health(Some("missing"))
            .await
            .expect_err("unknown database");
        assert!(
            error.to_string().contains("Unknown database session"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn health_does_not_take_the_lifecycle_lock() {
        let manager = SessionManager::new(test_pool());
        let session = manager.insert_test_session("sess-1").await;
        let _busy = session.begin_call("decompile");
        let _lifecycle = session.lifecycle.lock().await;

        let health =
            tokio::time::timeout(Duration::from_millis(200), manager.health(Some("sess-1")))
                .await
                .expect("server_health must not wait on lifecycle")
                .expect("session exists");
        let ServerHealth::One(one) = health else {
            panic!("expected a single-session snapshot");
        };
        assert_eq!(one.status, SessionHealthStatus::Busy);
        assert_eq!(one.busy_tool.as_deref(), Some("decompile"));
        assert_eq!(one.active_calls, 1);
        assert_eq!(session.active_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn health_without_database_summarizes_every_session() {
        let manager = SessionManager::new(test_pool());
        manager.insert_test_session("b").await;
        manager.insert_test_session("a").await;
        let ServerHealth::All(all) = manager.health(None).await.expect("health") else {
            panic!("expected a multi-session snapshot");
        };
        assert_eq!(all.count, 2);
        assert_eq!(all.sessions[0].session_id, "a");
        assert_eq!(all.sessions[1].session_id, "b");
        assert!(all
            .sessions
            .iter()
            .all(|item| item.status == SessionHealthStatus::Ok));
    }

    fn step_names(result: &WarmupResult) -> Vec<&str> {
        result.steps.iter().map(|step| step.step.as_str()).collect()
    }

    #[test]
    fn disabled_cache_and_hexrays_flags_do_not_claim_those_steps() {
        let warmup = assemble_open_warmup(true, true, WarmupResult::from_steps(Vec::new()));
        assert_eq!(step_names(&warmup), ["auto_wait"]);
        assert!(warmup.ok);
        let value = warmup.to_json();
        assert_eq!(
            value,
            json!({"ok": true, "steps": [{"step": "auto_wait", "ok": true, "ms": 0}]})
        );
        assert!(value["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .all(|step| {
                step.get("step").and_then(Value::as_str) != Some(BUILD_CACHES_STEP)
                    && step.get("step").and_then(Value::as_str) != Some(INIT_HEXRAYS_STEP)
            }));
    }

    #[test]
    fn all_warmup_flags_off_emits_no_steps() {
        let warmup = assemble_open_warmup(false, false, WarmupResult::from_steps(Vec::new()));
        assert!(warmup.ok);
        assert!(warmup.steps.is_empty());
        assert_eq!(warmup.to_json(), json!({"ok": true, "steps": []}));
    }

    #[test]
    fn auto_wait_reports_open_analysis_status_without_lying() {
        let failed = assemble_open_warmup(true, false, WarmupResult::from_steps(Vec::new()));
        assert!(!failed.ok);
        assert_eq!(failed.steps[0].step, "auto_wait");
        assert!(!failed.steps[0].ok);
        assert!(failed.steps[0].error.is_none());
    }

    #[test]
    fn worker_warmup_steps_keep_ms_and_errors() {
        let warmup = assemble_open_warmup(
            true,
            true,
            WarmupResult::from_steps(vec![
                WarmupStep::ok(BUILD_CACHES_STEP, 15),
                WarmupStep::err(INIT_HEXRAYS_STEP, 2, "Hex-Rays decompiler is not available"),
            ]),
        );
        assert!(!warmup.ok);
        assert_eq!(
            step_names(&warmup),
            ["auto_wait", BUILD_CACHES_STEP, INIT_HEXRAYS_STEP]
        );
        let value = warmup.to_json();
        assert_eq!(value["steps"][1]["ms"], 15);
        assert_eq!(
            value["steps"][2]["error"],
            "Hex-Rays decompiler is not available"
        );
        assert!(value["steps"][1].get("native").is_none());
        assert!(value["steps"][2].get("lazy").is_none());
    }

    #[test]
    fn warmup_rpc_failure_records_requested_steps() {
        let failed = warmup_rpc_failure(true, false, &ToolError::WorkerClosed);
        assert!(!failed.ok);
        assert_eq!(step_names(&failed), [BUILD_CACHES_STEP]);
        assert_eq!(
            failed.steps[0].error.as_deref(),
            Some("Worker channel closed")
        );
        let skipped = warmup_rpc_failure(false, false, &ToolError::WorkerClosed);
        assert!(skipped.ok);
        assert!(skipped.steps.is_empty());
    }
}
