//! Multi-process worker pool for HTTP sessions.

use crate::error::ToolError;
use crate::ida::lock::remove_mcp_lock_for_pid;
use crate::ida::observability::ProgressSender;
use crate::ida::query::StringQuery;
use crate::ida::remote;
use crate::ida::types::*;
use crate::ida::worker::MAX_TIMEOUT_SECS;
use futures_util::future::join_all;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{CallToolResult, ClientInfo, JsonObject};
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::ServiceExt;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const CHILD_CLOSE_TIMEOUT_SECS: u64 = 5;
pub(crate) const CHILD_TIMEOUT_GRACE_SECS: u64 = 10;

#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    pub max_workers: usize,
    pub min_workers: usize,
    pub worker_idle_timeout: Duration,
    pub worker_op_timeout: Duration,
    pub exe_path: PathBuf,
    /// Process-wide CLI arguments forwarded to worker processes.
    pub worker_args: Vec<OsString>,
}

/// Public tool-filter environment variables. Filtering is enforced by the
/// parent supervisor; private child workers must keep lifecycle/internal
/// tools such as `close_idb` and `analyze_funcs` available for the parent,
/// so these are stripped from the child environment.
const CHILD_FILTER_ENV_VARS: &[&str] = &[
    "IDA_MCP_TOOLSETS",
    "IDA_MCP_TOOLS",
    "IDA_MCP_EXCLUDE_TOOLS",
    "IDA_MCP_READ_ONLY",
];

#[derive(Clone)]
pub struct WorkerPool {
    inner: Arc<Mutex<PoolInner>>,
    config: Arc<WorkerPoolConfig>,
}

struct PoolInner {
    children: Vec<Arc<ChildSlot>>,
    spawning: HashSet<usize>,
    next_id: usize,
}

pub struct ChildSlot {
    id: usize,
    child: Mutex<PooledChild>,
    call_lock: Mutex<()>,
}

struct PooledChild {
    service: Option<RunningService<RoleClient, ParentClientHandler>>,
    peer: Peer<RoleClient>,
    pid: Option<u32>,
    stderr_task: JoinHandle<()>,
    state: ChildState,
    spawned_at: Instant,
    last_used: Instant,
    idb_path: Option<PathBuf>,
}

struct DeadWorker {
    service: Option<RunningService<RoleClient, ParentClientHandler>>,
    pid: Option<u32>,
    age_secs: u64,
    idb_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChildState {
    Idle,
    Leased { session_id: String },
    Closing,
    Dead,
}

#[derive(Clone)]
pub struct PooledWorkerHandle {
    pool: WorkerPool,
    slot: Arc<ChildSlot>,
    session_id: String,
    worker_id: usize,
}

#[derive(Clone)]
struct ParentClientHandler;

impl ClientHandler for ParentClientHandler {
    fn get_info(&self) -> ClientInfo {
        let mut info = ClientInfo::default();
        // Same trap as `ServerInfo::new`: the default is
        // `Implementation::from_build_env()`, which reports "rmcp" because it
        // expands `env!` inside rmcp. Child workers log this, so give them the
        // real parent identity.
        info.client_info = crate::server_implementation();
        info
    }
}

#[derive(Clone, Copy)]
enum WorkerRetireReason {
    Release,
    Call { tool: &'static str },
}

impl WorkerRetireReason {
    fn warn_missing_runtime(self, worker_id: usize, session_id: &str) {
        match self {
            Self::Release => {
                // This should only happen after the runtime is gone; there is
                // no safe async executor left to retire the worker.
                warn!(
                    worker_id,
                    session_id = %session_id,
                    "release cleanup was dropped outside a Tokio runtime; worker may remain unreleased"
                );
            }
            Self::Call { tool } => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    tool,
                    "pooled worker call was dropped outside a Tokio runtime; worker may remain leased"
                );
            }
        }
    }

    fn warn_retiring_worker(self, worker_id: usize, session_id: &str) {
        match self {
            Self::Release => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    "release cleanup was dropped before worker release completed; retiring worker"
                );
            }
            Self::Call { tool } => {
                warn!(
                    worker_id,
                    session_id = %session_id,
                    tool,
                    "pooled worker call was dropped before completion; retiring worker"
                );
            }
        }
    }
}

struct WorkerRetireGuard {
    pool: WorkerPool,
    slot: Arc<ChildSlot>,
    worker_id: usize,
    session_id: String,
    reason: WorkerRetireReason,
    runtime: Option<Handle>,
    armed: bool,
}

struct SpawnReservation {
    pool: WorkerPool,
    worker_id: usize,
    runtime: Option<Handle>,
    cleanup_slot: Option<Arc<ChildSlot>>,
    armed: bool,
}

impl WorkerRetireGuard {
    fn release(pool: WorkerPool, slot: Arc<ChildSlot>, handle: &PooledWorkerHandle) -> Self {
        Self {
            pool,
            slot,
            worker_id: handle.worker_id,
            session_id: handle.session_id.clone(),
            reason: WorkerRetireReason::Release,
            runtime: Handle::try_current().ok(),
            armed: true,
        }
    }

    fn call(handle: &PooledWorkerHandle, tool: &'static str) -> Self {
        Self {
            pool: handle.pool.clone(),
            slot: handle.slot.clone(),
            worker_id: handle.worker_id,
            session_id: handle.session_id.clone(),
            reason: WorkerRetireReason::Call { tool },
            runtime: Handle::try_current().ok(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for WorkerRetireGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let pool = self.pool.clone();
        let slot = self.slot.clone();
        let worker_id = self.worker_id;
        let session_id = self.session_id.clone();
        let reason = self.reason;
        let runtime = self.runtime.clone().or_else(|| Handle::try_current().ok());
        let Some(runtime) = runtime else {
            reason.warn_missing_runtime(worker_id, &session_id);
            return;
        };

        runtime.spawn(async move {
            reason.warn_retiring_worker(worker_id, &session_id);
            pool.mark_dead(&slot).await;
        });
    }
}

impl SpawnReservation {
    fn new(pool: WorkerPool, worker_id: usize) -> Self {
        Self {
            pool,
            worker_id,
            runtime: Handle::try_current().ok(),
            cleanup_slot: None,
            armed: true,
        }
    }

    fn worker_id(&self) -> usize {
        self.worker_id
    }

    async fn finish(mut self, slot: Option<Arc<ChildSlot>>) {
        self.cleanup_slot = slot.clone();
        self.pool
            .finish_spawn_reservation(self.worker_id, slot)
            .await;
        self.cleanup_slot = None;
        self.armed = false;
    }
}

impl Drop for SpawnReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let pool = self.pool.clone();
        let worker_id = self.worker_id;
        let cleanup_slot = self.cleanup_slot.take();
        let runtime = self.runtime.clone().or_else(|| Handle::try_current().ok());
        let Some(runtime) = runtime else {
            warn!(
                worker_id,
                "spawn reservation was dropped outside a Tokio runtime; capacity may remain reserved"
            );
            return;
        };

        runtime.spawn(async move {
            warn!(
                worker_id,
                "spawn reservation was dropped before worker installation completed"
            );
            pool.finish_spawn_reservation(worker_id, None).await;
            if let Some(slot) = cleanup_slot {
                pool.mark_dead(&slot).await;
            }
        });
    }
}

impl WorkerPool {
    pub fn new(config: WorkerPoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                children: Vec::new(),
                spawning: HashSet::new(),
                next_id: 0,
            })),
            config: Arc::new(config),
        }
    }

    pub async fn warm_min(&self) -> Result<(), ToolError> {
        let min = self.config.min_workers.min(self.config.max_workers);
        for _ in 0..min {
            let reservation = self.reserve_spawn_slot().await;
            self.spawn_reserved_slot(reservation, ChildState::Idle)
                .await?;
        }
        Ok(())
    }

    pub async fn lease(&self, session_id: &str) -> Result<PooledWorkerHandle, ToolError> {
        let session_id = session_id.to_string();
        let reservation = {
            let mut inner = self.inner.lock().await;
            let mut active = inner.spawning.len();
            let mut dead_ids = Vec::new();

            for slot in &inner.children {
                let mut child = slot.child.lock().await;
                if child.state == ChildState::Dead {
                    dead_ids.push(slot.id);
                    continue;
                }
                active += 1;
                if child.state == ChildState::Idle {
                    child.state = ChildState::Leased {
                        session_id: session_id.clone(),
                    };
                    child.last_used = Instant::now();
                    info!(
                        worker_id = slot.id,
                        session_id = %session_id,
                        "leased idle IDA child worker"
                    );
                    return Ok(PooledWorkerHandle {
                        pool: self.clone(),
                        slot: slot.clone(),
                        session_id,
                        worker_id: slot.id,
                    });
                }
            }

            if !dead_ids.is_empty() {
                inner.children.retain(|slot| !dead_ids.contains(&slot.id));
            }

            if active >= self.config.max_workers {
                return Err(ToolError::PoolExhausted {
                    active,
                    max: self.config.max_workers,
                });
            }

            self.reserve_spawn_slot_locked(&mut inner)
        };

        let id = reservation.worker_id();
        let slot = self
            .spawn_reserved_slot(
                reservation,
                ChildState::Leased {
                    session_id: session_id.clone(),
                },
            )
            .await?;
        info!(
            worker_id = id,
            session_id = %session_id,
            "spawned leased IDA child worker"
        );
        Ok(PooledWorkerHandle {
            pool: self.clone(),
            slot,
            session_id,
            worker_id: id,
        })
    }

    async fn spawn_reserved_slot(
        &self,
        reservation: SpawnReservation,
        initial_state: ChildState,
    ) -> Result<Arc<ChildSlot>, ToolError> {
        let id = reservation.worker_id();
        match self.spawn_slot(id, initial_state).await {
            Ok(slot) => {
                reservation.finish(Some(slot.clone())).await;
                Ok(slot)
            }
            Err(err) => {
                reservation.finish(None).await;
                Err(err)
            }
        }
    }

    async fn reserve_spawn_slot(&self) -> SpawnReservation {
        let mut inner = self.inner.lock().await;
        self.reserve_spawn_slot_locked(&mut inner)
    }

    fn reserve_spawn_slot_locked(&self, inner: &mut PoolInner) -> SpawnReservation {
        let id = inner.next_id;
        inner.next_id += 1;
        inner.spawning.insert(id);
        SpawnReservation::new(self.clone(), id)
    }

    async fn finish_spawn_reservation(&self, worker_id: usize, slot: Option<Arc<ChildSlot>>) {
        let mut inner = self.inner.lock().await;
        inner.spawning.remove(&worker_id);
        if let Some(slot) = slot {
            inner.children.push(slot);
        }
    }

    fn worker_command(&self) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new(&self.config.exe_path);
        cmd.args(&self.config.worker_args);
        cmd.arg("worker");
        for var in CHILD_FILTER_ENV_VARS {
            cmd.env_remove(var);
        }
        cmd.kill_on_drop(true);
        // A terminal Ctrl+C signals the whole foreground process group. Sharing
        // the supervisor's group, every worker took SIGINT at the same instant
        // the supervisor did and raced its own shutdown against the parent's
        // `close_idb` — which then read the closed transport as a dead child and
        // sent SIGKILL, mid-save, losing the database. The supervisor is the
        // only thing that knows which databases are open, so it is the only
        // thing that gets to close them.
        #[cfg(unix)]
        cmd.process_group(0);
        cmd
    }

    async fn spawn_slot(
        &self,
        id: usize,
        initial_state: ChildState,
    ) -> Result<Arc<ChildSlot>, ToolError> {
        let cmd = self.worker_command();

        let (transport, stderr) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| {
                ToolError::RemoteProtocol(format!("failed to spawn worker {id}: {err}"))
            })?;
        let pid = transport.id();
        let stderr_task = spawn_stderr_relay(id, stderr);
        let handler = ParentClientHandler;
        let service = handler.serve(transport).await.map_err(|err| {
            ToolError::RemoteProtocol(format!("failed to initialize worker {id}: {err}"))
        })?;
        let peer = service.peer().clone();
        Ok(Arc::new(ChildSlot {
            id,
            child: Mutex::new(PooledChild {
                service: Some(service),
                peer,
                pid,
                stderr_task,
                state: initial_state,
                spawned_at: Instant::now(),
                last_used: Instant::now(),
                idb_path: None,
            }),
            call_lock: Mutex::new(()),
        }))
    }

    pub async fn release(&self, handle: PooledWorkerHandle) -> Result<(), ToolError> {
        self.release_with_save(handle, true).await
    }

    pub async fn release_with_save(
        &self,
        handle: PooledWorkerHandle,
        save: bool,
    ) -> Result<(), ToolError> {
        let result = self.release_inner(&handle, save).await;
        if self.slot_is_idle(&handle.slot).await {
            self.schedule_idle_reap(handle.slot.clone());
        }
        result
    }

    async fn slot_is_idle(&self, slot: &Arc<ChildSlot>) -> bool {
        let child = slot.child.lock().await;
        child.state == ChildState::Idle
    }

    async fn release_inner(
        &self,
        handle: &PooledWorkerHandle,
        save: bool,
    ) -> Result<(), ToolError> {
        let mut release_guard =
            WorkerRetireGuard::release(self.clone(), handle.slot.clone(), handle);
        let _call_guard = handle.slot.call_lock.lock().await;
        let peer = {
            let mut child = handle.slot.child.lock().await;
            if child.state == ChildState::Dead {
                release_guard.disarm();
                return Ok(());
            }
            child.state = ChildState::Closing;
            child.peer.clone()
        };

        let args = remote::json_object(json!({ "save": save }))?;
        let close = tokio::time::timeout(
            Duration::from_secs(CHILD_CLOSE_TIMEOUT_SECS),
            remote::call_tool(&peer, "close_idb", args),
        )
        .await;

        let close_error = match close {
            Ok(Ok(result)) if result.is_error != Some(true) => None,
            Ok(Ok(result)) => remote::result_error(&result, "close_idb"),
            Ok(Err(err)) => Some(err),
            Err(_) => Some(ToolError::Timeout(CHILD_CLOSE_TIMEOUT_SECS)),
        };

        if let Some(err) = close_error {
            // A failed close does not establish that the child released its
            // IDB, so the worker must never become leasable again.
            warn!(
                worker_id = handle.worker_id,
                session_id = %handle.session_id,
                error = %err,
                "retiring IDA child worker after close_idb failure"
            );
            self.mark_dead(&handle.slot).await;
            release_guard.disarm();
            return Err(err);
        }

        let mut child = handle.slot.child.lock().await;
        if child.state == ChildState::Dead {
            release_guard.disarm();
            return Ok(());
        }
        child.state = ChildState::Idle;
        child.last_used = Instant::now();
        child.idb_path = None;
        release_guard.disarm();
        info!(
            worker_id = handle.worker_id,
            session_id = %handle.session_id,
            "released IDA child worker"
        );
        Ok(())
    }

    fn schedule_idle_reap(&self, slot: Arc<ChildSlot>) {
        let pool = self.clone();
        tokio::spawn(async move {
            let timeout = pool.config.worker_idle_timeout;
            if timeout.is_zero() {
                return;
            }
            let sleep_started = Instant::now();
            tokio::time::sleep(timeout).await;

            pool.mark_stale_idle_dead(&slot, sleep_started).await;
        });
    }

    pub async fn mark_dead(&self, slot: &Arc<ChildSlot>) {
        self.mark_dead_inner(slot, true).await;
    }

    async fn mark_dead_without_replacement(&self, slot: &Arc<ChildSlot>) {
        self.mark_dead_inner(slot, false).await;
    }

    async fn mark_dead_inner(&self, slot: &Arc<ChildSlot>, replenish: bool) {
        let dead = self.take_dead_worker(slot).await;
        self.forget_slot(slot.id).await;
        if let Some(dead) = dead {
            Self::finish_dead_worker(slot.id, dead).await;
        }
        if replenish {
            self.ensure_min_workers().await;
        }
    }

    async fn mark_stale_idle_dead(&self, slot: &Arc<ChildSlot>, sleep_started: Instant) {
        let Some(dead) = self
            .take_stale_idle_worker_if_above_min(slot, sleep_started)
            .await
        else {
            return;
        };
        info!(worker_id = slot.id, "reaping idle IDA child worker");
        self.forget_slot(slot.id).await;
        Self::finish_dead_worker(slot.id, dead).await;
    }

    async fn forget_slot(&self, worker_id: usize) {
        let mut inner = self.inner.lock().await;
        inner.children.retain(|slot| slot.id != worker_id);
    }

    async fn take_dead_worker(&self, slot: &Arc<ChildSlot>) -> Option<DeadWorker> {
        let mut child = slot.child.lock().await;
        if child.state == ChildState::Dead {
            return None;
        }
        Some(Self::take_dead_worker_locked(&mut child))
    }

    async fn take_stale_idle_worker_if_above_min(
        &self,
        slot: &Arc<ChildSlot>,
        sleep_started: Instant,
    ) -> Option<DeadWorker> {
        let inner = self.inner.lock().await;
        let mut live_count = inner.spawning.len();
        for child_slot in &inner.children {
            let child = child_slot.child.lock().await;
            if child.state != ChildState::Dead {
                live_count += 1;
            }
        }
        if live_count <= self.config.min_workers {
            return None;
        }

        let mut child = slot.child.lock().await;
        if child.state != ChildState::Idle || child.last_used > sleep_started {
            return None;
        }
        Some(Self::take_dead_worker_locked(&mut child))
    }

    fn take_dead_worker_locked(child: &mut PooledChild) -> DeadWorker {
        child.state = ChildState::Dead;
        let idb_path = child.idb_path.take();
        let pid = child.pid;
        let age_secs = child.spawned_at.elapsed().as_secs();
        let service = child.service.take();
        child.stderr_task.abort();
        DeadWorker {
            service,
            pid,
            age_secs,
            idb_path,
        }
    }

    async fn finish_dead_worker(worker_id: usize, mut dead: DeadWorker) {
        if let Some(mut service) = dead.service.take() {
            let _ = service
                .close_with_timeout(Duration::from_secs(CHILD_CLOSE_TIMEOUT_SECS))
                .await;
        }
        if let Some(idb_path) = dead.idb_path.as_ref() {
            remove_mcp_lock_for_pid(idb_path, dead.pid);
        }
        warn!(
            worker_id,
            ?dead.pid,
            age_secs = dead.age_secs,
            "marked IDA child worker dead"
        );
    }

    async fn ensure_min_workers(&self) {
        let min_workers = self.config.min_workers.min(self.config.max_workers);
        if min_workers == 0 {
            return;
        }

        loop {
            let reservation = {
                let mut inner = self.inner.lock().await;
                let live_or_reserved = inner.spawning.len() + inner.children.len();
                if live_or_reserved >= min_workers || live_or_reserved >= self.config.max_workers {
                    return;
                }
                self.reserve_spawn_slot_locked(&mut inner)
            };

            let worker_id = reservation.worker_id();
            if let Err(err) = self
                .spawn_reserved_slot(reservation, ChildState::Idle)
                .await
            {
                warn!(worker_id, error = %err, "failed to replenish minimum pooled worker");
                return;
            }
        }
    }

    pub async fn shutdown_all(&self) {
        let slots = {
            let inner = self.inner.lock().await;
            inner.children.clone()
        };
        join_all(slots.into_iter().map(|slot| {
            let pool = self.clone();
            async move {
                pool.mark_dead_without_replacement(&slot).await;
            }
        }))
        .await;
    }

    #[cfg(test)]
    async fn live_or_reserved_count(&self) -> usize {
        let inner = self.inner.lock().await;
        let mut count = inner.spawning.len();
        for slot in &inner.children {
            let child = slot.child.lock().await;
            if child.state != ChildState::Dead {
                count += 1;
            }
        }
        count
    }

    fn worker_op_timeout(&self, requested: Option<u64>) -> Duration {
        let configured = self.config.worker_op_timeout;
        requested
            .map(|seconds| {
                seconds
                    .min(MAX_TIMEOUT_SECS)
                    .saturating_add(CHILD_TIMEOUT_GRACE_SECS)
            })
            .map(Duration::from_secs)
            .map(|requested| requested.min(configured))
            .unwrap_or(configured)
    }
}

impl PooledWorkerHandle {
    pub fn worker_id(&self) -> usize {
        self.worker_id
    }

    async fn call_tool(
        &self,
        tool: &'static str,
        args: JsonObject,
        timeout: Duration,
        cancel: Option<CancellationToken>,
    ) -> Result<CallToolResult, ToolError> {
        let _call_guard = self.slot.call_lock.lock().await;
        let peer = {
            let child = self.slot.child.lock().await;
            match &child.state {
                ChildState::Leased { session_id } if session_id == &self.session_id => {
                    child.peer.clone()
                }
                ChildState::Dead => {
                    return Err(ToolError::WorkerCrashed {
                        worker_id: self.worker_id,
                        last_op: tool.to_string(),
                    });
                }
                other => {
                    return Err(ToolError::RemoteProtocol(format!(
                        "worker {} is not leased to session {} (state: {other:?})",
                        self.worker_id, self.session_id
                    )));
                }
            }
        };

        let request = remote::call_tool(&peer, tool, args);
        tokio::pin!(request);
        let mut retire_guard = WorkerRetireGuard::call(self, tool);

        let result = if let Some(cancel) = cancel {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    self.pool.mark_dead(&self.slot).await;
                    retire_guard.disarm();
                    return Err(ToolError::Cancelled(format!(
                        "cancelled {tool}; killed worker {}",
                        self.worker_id
                    )));
                }
                result = tokio::time::timeout(timeout, &mut request) => result,
            }
        } else {
            tokio::time::timeout(timeout, &mut request).await
        };

        match result {
            Ok(Ok(result)) => {
                retire_guard.disarm();
                Ok(result)
            }
            Ok(Err(err)) => {
                self.pool.mark_dead(&self.slot).await;
                retire_guard.disarm();
                Err(ToolError::WorkerCrashed {
                    worker_id: self.worker_id,
                    last_op: format!("{tool}: {err}"),
                })
            }
            Err(_) => {
                self.pool.mark_dead(&self.slot).await;
                retire_guard.disarm();
                Err(ToolError::TimeoutDetailed(format!(
                    "{tool} exceeded worker operation timeout of {} seconds; killed worker {}",
                    timeout.as_secs(),
                    self.worker_id
                )))
            }
        }
    }
}

/// One supervisor session's hold on one child worker.
///
/// It knows how to take a lease (`open_idb`), give it back (`close_idb`), say
/// whether it still has one, and forward anything else to the child by name.
/// It deliberately does not know what the tools are: the child publishes the
/// same 85 that this process does, and the supervisor validated the name
/// against its own catalog before getting here.
///
/// Do not add a typed method per tool here. That is a second, parallel
/// spelling of the whole surface, each one translating a request struct into
/// the JSON the child is going to be sent anyway. [`Self::call_compat_result`]
/// is the only way in.
pub struct PooledSessionState {
    pool: WorkerPool,
    session_id: String,
    handle: Arc<Mutex<Option<PooledWorkerHandle>>>,
    runtime: Option<Handle>,
}

impl PooledSessionState {
    pub fn new(pool: WorkerPool, session_id: String) -> Self {
        Self {
            pool,
            session_id,
            handle: Arc::new(Mutex::new(None)),
            runtime: Handle::try_current().ok(),
        }
    }

    /// Return this session's worker, leasing one if it has none yet. The bool
    /// says whether the lease is new, which decides who releases it if the
    /// open that follows fails.
    async fn lease_for_open(&self) -> Result<(PooledWorkerHandle, bool), ToolError> {
        let mut guard = self.handle.lock().await;
        if let Some(handle) = guard.as_ref() {
            return Ok((handle.clone(), false));
        }
        let handle = self.pool.lease(&self.session_id).await?;
        *guard = Some(handle.clone());
        Ok((handle, true))
    }

    async fn required_handle(&self) -> Result<PooledWorkerHandle, ToolError> {
        let guard = self.handle.lock().await;
        guard.as_ref().cloned().ok_or(ToolError::NoDatabaseOpen)
    }

    async fn take_handle(&self) -> Option<PooledWorkerHandle> {
        self.handle.lock().await.take()
    }

    async fn release_current_handle(&self) {
        if let Some(handle) = self.take_handle().await {
            let _ = self.pool.release(handle).await;
        }
    }

    async fn clear_handle_if_worker(&self, worker_id: usize) {
        let mut guard = self.handle.lock().await;
        if guard
            .as_ref()
            .is_some_and(|handle| handle.worker_id == worker_id)
        {
            *guard = None;
        }
    }

    pub(crate) async fn has_live_database(&self) -> bool {
        let guard = self.handle.lock().await;
        let Some(handle) = guard.as_ref() else {
            return false;
        };
        let child = handle.slot.child.lock().await;
        matches!(
            &child.state,
            ChildState::Leased { session_id } if session_id == &handle.session_id
        ) && !child.peer.is_transport_closed()
    }

    /// Call a child tool on this session's leased worker and hand back the
    /// child's answer as it came.
    ///
    /// Worker *health* is decided here, not by the caller: a transport failure,
    /// or an error meaning the child is no longer usable, clears this session's
    /// lease and retires the worker before the error travels on. What a
    /// tool-level `isError` means is the caller's business — the supervisor
    /// forwards one to its client, warmup counts one as a failed probe — so
    /// this returns it inside `Ok`.
    async fn dispatch(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<CallToolResult, ToolError> {
        let handle = self.required_handle().await?;
        let timeout = self.pool.worker_op_timeout(timeout_secs);
        let result = match handle
            .call_tool(tool, remote::json_object(args)?, timeout, cancel)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                self.clear_handle_if_worker(handle.worker_id).await;
                return Err(err);
            }
        };
        if let Some(err) = remote::result_error(&result, tool)
            && child_tool_error_retires_worker(&err)
        {
            self.clear_handle_if_worker(handle.worker_id).await;
            self.pool.mark_dead(&handle.slot).await;
        }
        Ok(result)
    }

    /// Forward a supervisor tool call and keep the worker's `CallToolResult`.
    ///
    /// Transport / lifecycle failures (crash, timeout, cancel, closed channel)
    /// stay `Err` so the caller can drop the session. Tool-level `isError`
    /// (`IdaError` / `IdaErrorDetail`) is returned as `Ok` so the supervisor can
    /// forward `content` + `structuredContent` + `isError`.
    pub async fn call_compat_result(
        &self,
        tool: &'static str,
        args: Value,
        timeout_secs: Option<u64>,
        cancel: Option<CancellationToken>,
    ) -> Result<CallToolResult, ToolError> {
        let result = self.dispatch(tool, args, timeout_secs, cancel).await?;
        if let Some(err) = remote::result_error(&result, tool)
            && remote::is_lifecycle_error(&err)
        {
            return Err(err);
        }
        Ok(remote::strip_call_tool_result(result))
    }

    /// Probe the leased child with one tool call, reading its answer as `T`.
    ///
    /// The only caller is [`Self::warmup`], which reports what it found: a
    /// tool-level failure and a response the parse rejects are both findings,
    /// so both arrive as `Err`.
    async fn probe_json<T: DeserializeOwned>(
        &self,
        tool: &'static str,
        args: Value,
    ) -> Result<T, ToolError> {
        let result = self.dispatch(tool, args, None, None).await?;
        remote::parse_json(result, tool)
    }

    /// See [`Self::probe_json`]; the Hex-Rays probe reads text, not JSON.
    ///
    /// The child error is classified before `result_text` sees it, because
    /// `classify_hexrays_probe` reads the message and a lifecycle error renders
    /// differently from a plain `IdaError`.
    async fn probe_text(&self, tool: &'static str, args: Value) -> Result<String, ToolError> {
        let result = self.dispatch(tool, args, None, None).await?;
        if let Some(err) = remote::result_error(&result, tool) {
            return Err(err);
        }
        remote::result_text(&result, tool)
    }

    /// Post-open warmup on the leased child.
    ///
    /// Cache rebuild goes through `strings` at offset 0 (same rebuild as the
    /// worker request). Hex-Rays init is a private worker request; the child
    /// is probed via `decompile`, which checks availability before lookup.
    pub async fn warmup(
        &self,
        build_caches: bool,
        init_hexrays: bool,
    ) -> Result<WarmupResult, ToolError> {
        use crate::ida::handlers::warmup::{
            classify_hexrays_probe, elapsed_ms, BUILD_CACHES_STEP, INIT_HEXRAYS_STEP,
        };

        let mut steps = Vec::new();
        if build_caches {
            let started = Instant::now();
            match self
                .probe_json::<StringListResult>(
                    "strings",
                    strings_child_args(&StringQuery::paged(0, 1), None),
                )
                .await
            {
                Ok(_) => steps.push(WarmupStep::ok(BUILD_CACHES_STEP, elapsed_ms(started))),
                Err(error) => steps.push(WarmupStep::err(
                    BUILD_CACHES_STEP,
                    elapsed_ms(started),
                    error.to_string(),
                )),
            }
        }
        if init_hexrays {
            let started = Instant::now();
            match self
                .probe_text(
                    "decompile",
                    json!({ "address": remote::hex_addr(u64::MAX) }),
                )
                .await
            {
                Ok(_) => steps.push(WarmupStep::ok(INIT_HEXRAYS_STEP, elapsed_ms(started))),
                Err(error) => match classify_hexrays_probe(&error) {
                    Ok(()) => steps.push(WarmupStep::ok(INIT_HEXRAYS_STEP, elapsed_ms(started))),
                    Err(message) => steps.push(WarmupStep::err(
                        INIT_HEXRAYS_STEP,
                        elapsed_ms(started),
                        message,
                    )),
                },
            }
        }
        Ok(WarmupResult::from_steps(steps))
    }

    /// Open a database on this session's leased worker.
    ///
    /// `progress_tx` is accepted and dropped: progress notifications are the
    /// child's own, and the supervisor forwards the child's answer rather than
    /// narrating it.
    pub async fn open_observed(
        &self,
        spec: OpenSpec,
        timeout_secs: Option<u64>,
        _progress_tx: Option<ProgressSender>,
        cancel: Option<CancellationToken>,
    ) -> Result<DbInfo, ToolError> {
        let (handle, fresh_lease) = self.lease_for_open().await?;
        let timeout = self.pool.worker_op_timeout(timeout_secs);
        let result = handle
            .call_tool(
                "open_idb",
                remote::json_object(open_idb_child_args(&spec, timeout_secs))?,
                timeout,
                cancel,
            )
            .await;

        match result.and_then(|result| remote::parse_json::<DbInfo>(result, "open_idb")) {
            Ok(info) => {
                let mut child = handle.slot.child.lock().await;
                child.idb_path = Some(PathBuf::from(&info.path));
                Ok(info)
            }
            Err(err) => {
                if open_error_releases_lease(fresh_lease, &err) {
                    self.release_current_handle().await;
                }
                Err(err)
            }
        }
    }

    pub async fn close_with_save(&self, save: bool) -> Result<(), ToolError> {
        let Some(handle) = self.take_handle().await else {
            return Err(ToolError::NoDatabaseOpen);
        };
        self.pool.release_with_save(handle, save).await
    }
}

impl Drop for PooledSessionState {
    fn drop(&mut self) {
        let pool = self.pool.clone();
        let handle_slot = self.handle.clone();
        let runtime = Handle::try_current().ok().or_else(|| self.runtime.clone());
        let Some(runtime) = runtime else {
            warn!(
                session_id = %self.session_id,
                "pooled session dropped outside a Tokio runtime; worker lease may remain active"
            );
            return;
        };
        runtime.spawn(async move {
            let Some(handle) = handle_slot.lock().await.take() else {
                return;
            };
            let _ = pool.release(handle).await;
        });
    }
}

fn open_idb_child_args(spec: &OpenSpec, timeout_secs: Option<u64>) -> Value {
    json!({
        "path": spec.path,
        "load_debug_info": spec.load_debug_info,
        "debug_info_path": spec.debug_info_path,
        "debug_info_verbose": spec.debug_info_verbose,
        "force": spec.force,
        "rebuild": spec.rebuild,
        "file_type": spec.file_type,
        "auto_analyse": spec.auto_analyse,
        "_worker_extra_args": spec.extra_args,
        "_worker_idb_out": spec.idb_out,
        "timeout_secs": timeout_secs,
    })
}

/// Re-flatten a string query into the tool arguments a pooled worker takes.
fn strings_child_args(query: &StringQuery, timeout_secs: Option<u64>) -> Value {
    json!({
        "offset": query.offset,
        "limit": query.limit,
        "filter": query.filter,
        "regex": query.regex,
        "min_length": query.min_length,
        "max_length": query.max_length,
        "sort_by": query.sort_by,
        "descending": query.descending,
        "timeout_secs": timeout_secs,
    })
}

/// Whether a tool-level failure means this worker must not be used again.
///
/// `WorkerRetired` is the child saying so itself: a guarded call took SIGSEGV
/// or SIGBUS, and the process that answered is on its way out (see
/// [`crate::crash_guard`]). Retiring it here is what makes the answer true from
/// the parent's side — the lease is dropped, the child is killed, and the pool
/// replenishes — rather than waiting for the child's own exit to arrive as a
/// closed transport on some later, unrelated call.
fn child_tool_error_retires_worker(err: &ToolError) -> bool {
    matches!(
        err,
        ToolError::WorkerClosed
            | ToolError::WorkerCrashed { .. }
            | ToolError::WorkerRetired(_)
            | ToolError::RemoteProtocol(_)
    )
}

fn open_error_releases_lease(fresh_lease: bool, err: &ToolError) -> bool {
    fresh_lease
        || matches!(
            err,
            ToolError::Timeout(_)
                | ToolError::TimeoutDetailed(_)
                | ToolError::Cancelled(_)
                | ToolError::WorkerCrashed { .. }
                | ToolError::WorkerClosed
                | ToolError::WorkerRetired(_)
        )
}

const STDERR_CHUNK_BYTES: usize = 4096;
const STDERR_LINE_LIMIT_BYTES: usize = 16 * 1024;

fn spawn_stderr_relay(
    worker_id: usize,
    stderr: Option<tokio::process::ChildStderr>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(mut stderr) = stderr else {
            return;
        };
        let mut chunk = [0_u8; STDERR_CHUNK_BYTES];
        let mut pending = Vec::new();

        loop {
            match stderr.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => drain_stderr_chunk(worker_id, &mut pending, &chunk[..n]),
                Err(err) => {
                    warn!(worker_id, error = %err, "failed to read child stderr");
                    break;
                }
            }
        }

        if !pending.is_empty() {
            log_stderr_line(worker_id, &pending);
        }
    })
}

fn drain_stderr_chunk(worker_id: usize, pending: &mut Vec<u8>, mut chunk: &[u8]) {
    while let Some(pos) = chunk.iter().position(|byte| *byte == b'\n') {
        pending.extend_from_slice(&chunk[..pos]);
        log_stderr_line(worker_id, pending);
        pending.clear();
        chunk = &chunk[pos + 1..];
    }

    pending.extend_from_slice(chunk);
    if pending.len() > STDERR_LINE_LIMIT_BYTES {
        let truncated = &pending[..STDERR_LINE_LIMIT_BYTES];
        let line = String::from_utf8_lossy(truncated);
        debug!(target: "ida_mcp::worker_stderr", worker_id, line = %line, truncated = true);
        pending.clear();
    }
}

fn log_stderr_line(worker_id: usize, line: &[u8]) {
    let line = String::from_utf8_lossy(line);
    debug!(target: "ida_mcp::worker_stderr", worker_id, line = %line);
}

#[cfg(test)]
mod tests {
    use crate::error::ToolError;
    use crate::ida::pool::{
        child_tool_error_retires_worker, open_error_releases_lease, open_idb_child_args,
        WorkerPool, WorkerPoolConfig,
    };
    use crate::ida::types::OpenSpec;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_pool(max_workers: usize) -> WorkerPool {
        WorkerPool::new(WorkerPoolConfig {
            max_workers,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(600),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        })
    }

    #[test]
    fn pooled_child_workers_ignore_public_tool_filters() {
        let pool = test_pool(1);
        let cmd = pool.worker_command();
        let cleared: Vec<&str> = cmd
            .as_std()
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .filter_map(|(key, _)| key.to_str())
            .collect();

        for var in crate::ida::pool::CHILD_FILTER_ENV_VARS {
            assert!(
                cleared.contains(var),
                "pooled child workers must not inherit {var}; they need lifecycle tools"
            );
        }
    }

    #[test]
    fn explicit_child_timeout_gets_parent_watchdog_grace() {
        let pool = WorkerPool::new(WorkerPoolConfig {
            max_workers: 1,
            min_workers: 0,
            worker_idle_timeout: Duration::from_secs(300),
            worker_op_timeout: Duration::from_secs(1800),
            exe_path: PathBuf::from("/does/not/spawn/in/this/test"),
            worker_args: Vec::new(),
        });

        assert_eq!(pool.worker_op_timeout(Some(120)), Duration::from_secs(130));
        assert_eq!(pool.worker_op_timeout(Some(600)), Duration::from_secs(610));
        assert_eq!(
            pool.worker_op_timeout(Some(9999)),
            Duration::from_secs(610),
            "child foreground timeout is capped before adding parent grace"
        );
    }

    /// `open_idb` is the one tool the parent still builds child arguments for
    /// by hand; every other tool now reaches the child through
    /// [`PooledSessionState::call_compat_result`], which forwards the
    /// caller's arguments unchanged.
    #[test]
    fn pooled_open_child_args_forward_timeouts() {
        let open_args = open_idb_child_args(
            &OpenSpec {
                path: "/tmp/a".to_string(),
                load_debug_info: true,
                debug_info_path: Some("/tmp/a.dSYM".to_string()),
                debug_info_verbose: true,
                file_type: Some("pe".to_string()),
                auto_analyse: true,
                extra_args: vec!["-A".to_string()],
                idb_out: Some("/tmp/a.out.i64".to_string()),
                ..Default::default()
            },
            Some(600),
        );
        assert_eq!(open_args["timeout_secs"], json!(600));
        assert_eq!(open_args["rebuild"], json!(false));
        assert_eq!(open_args["_worker_idb_out"], json!("/tmp/a.out.i64"));
    }

    #[test]
    fn child_tool_error_retire_decision_keeps_routine_timeouts_reusable() {
        assert!(!child_tool_error_retires_worker(
            &ToolError::TimeoutDetailed("run_script timed out after 5 seconds".to_string())
        ));
        assert!(!child_tool_error_retires_worker(&ToolError::Cancelled(
            "run_script cancelled".to_string()
        )));
        assert!(child_tool_error_retires_worker(&ToolError::WorkerClosed));
    }

    /// A worker that jumped out of a signal handler is not reusable, and the
    /// pool must not wait for its exit to notice: no later call may be routed
    /// to that process.
    #[test]
    fn a_worker_that_caught_a_signal_is_retired_and_gives_up_its_lease() {
        let retired = crate::crash_guard::retired_error(11);
        assert!(child_tool_error_retires_worker(&retired));
        assert!(open_error_releases_lease(false, &retired));
    }

    #[test]
    fn open_failure_releases_fresh_lease() {
        assert!(open_error_releases_lease(
            true,
            &ToolError::IdaError("A database is already open".to_string())
        ));
    }

    #[test]
    fn open_failure_keeps_existing_lease_for_ida_errors() {
        assert!(!open_error_releases_lease(
            false,
            &ToolError::IdaError("A database is already open".to_string())
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_worker_crash() {
        assert!(open_error_releases_lease(
            false,
            &ToolError::WorkerCrashed {
                worker_id: 7,
                last_op: "open_idb".to_string(),
            }
        ));
    }

    /// A call before `open_idb` reports that, rather than leasing a worker to
    /// answer it. Only `open_idb` may take a lease; every other tool needs the
    /// one this session already holds.
    #[tokio::test]
    async fn a_call_before_open_reports_no_database() {
        let state =
            crate::ida::pool::PooledSessionState::new(test_pool(1), "no-open-test".to_string());

        assert!(matches!(
            state.required_handle().await,
            Err(ToolError::NoDatabaseOpen)
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_cancellation() {
        assert!(open_error_releases_lease(
            false,
            &ToolError::Cancelled("cancelled open_idb".to_string())
        ));
    }

    #[test]
    fn open_failure_releases_existing_lease_for_closed_worker() {
        assert!(open_error_releases_lease(false, &ToolError::WorkerClosed));
    }

    #[tokio::test]
    async fn spawn_reservation_counts_toward_pool_capacity() {
        let pool = test_pool(1);
        let reservation = pool.reserve_spawn_slot().await;

        assert_eq!(pool.live_or_reserved_count().await, 1);
        let err = match pool.lease("session-b").await {
            Ok(_) => panic!("lease should fail while the only slot is reserved"),
            Err(err) => err,
        };
        match err {
            ToolError::PoolExhausted { active, max } => {
                assert_eq!(active, 1);
                assert_eq!(max, 1);
            }
            other => panic!("unexpected lease error: {other}"),
        }

        reservation.finish(None).await;
        assert_eq!(pool.live_or_reserved_count().await, 0);
    }

    #[tokio::test]
    async fn dropped_spawn_reservation_releases_pool_capacity() {
        let pool = test_pool(1);
        let reservation = pool.reserve_spawn_slot().await;
        drop(reservation);

        for _ in 0..10 {
            if pool.live_or_reserved_count().await == 0 {
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("dropped spawn reservation did not release capacity");
    }
}
