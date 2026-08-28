//! Crash isolation for IDA SDK FFI calls.
//!
//! The Hex-Rays decompiler and certain IDA SDK mutation ops can segfault.
//! This module catches SIGSEGV/SIGBUS via sigsetjmp/siglongjmp and converts
//! them to errors instead of killing the process before it can say what
//! happened.
//!
//! # What a catch is worth, and what it is not
//!
//! Surviving the signal buys one thing: a *diagnosis*. The jump out of the
//! handler skipped every Rust and C++ destructor between the crash and here, so
//! locks IDA held are still held, objects it was midway through are half-built,
//! and its allocator may be corrupt. A process in that state can produce wrong
//! answers rather than obvious failures, which is worse than crashing.
//!
//! So a catch is terminal for the process, not just for the call:
//!
//! - the signal is recorded here, and every later guarded call refuses without
//!   entering IDA (see [`caught_signal`]);
//! - the worker loop rejects every later request with [`retired_error`], so the
//!   answer says *why* rather than timing out;
//! - a watchdog thread gives that answer time to reach the client and then
//!   `_exit`s — no atexit handlers, no destructors, nothing that would walk the
//!   heap this module has just declared untrustworthy.
//!
//! Under `serve`, the supervisor reads [`WORKER_RETIRED_MARKER`] out of the
//! error, retires that child, and invalidates only the session that was using
//! it; the other sessions and the server itself are unaffected. Run as a bare
//! `worker` there is no parent to do that, so the process exits and the client
//! must start a new one — the same conclusion, reached with nobody to hide it.

use std::sync::atomic::{AtomicI32, Ordering};

use crate::error::ToolError;

/// The phrase that carries a retirement across the process boundary.
///
/// A child worker answers over MCP, where a `ToolError` is flattened to
/// `isError` plus a sentence, so the parent classifies by message
/// (`crate::ida::remote::classify_child_error`). Lower-case: the match is done
/// on a lower-cased copy of the message.
pub const WORKER_RETIRED_MARKER: &str = "worker retired after a fatal signal";

/// How long the answer gets to reach the client before the process exits.
///
/// It only has to cross an in-process channel and one stdout write. Seconds
/// rather than milliseconds because the cost of waiting too long is that a
/// worker already excluded from the pool lingers a moment, and the cost of not
/// waiting long enough is a client that never learns why its call died.
#[cfg(unix)]
const RESPONSE_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// The signal a guarded call took, or 0. Written once, read from the worker
/// loop on every request.
static CAUGHT_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// The signal this process caught, if it caught one.
///
/// Once this answers `Some`, it answers `Some` forever: nothing rehabilitates
/// a process that jumped out of a signal handler.
pub fn caught_signal() -> Option<i32> {
    match CAUGHT_SIGNAL.load(Ordering::Acquire) {
        0 => None,
        signal => Some(signal),
    }
}

/// The error every request after a caught signal is answered with.
///
/// Deliberately one sentence about the past and one about what to do next: the
/// reader is an agent that just lost a call and has to decide whether to retry
/// it, and the answer is that retrying *here* cannot work.
pub fn retired_error(signal: i32) -> ToolError {
    ToolError::WorkerRetired(format!(
        "{WORKER_RETIRED_MARKER}: an earlier operation crashed inside the IDA SDK \
         (signal {signal}), so this worker is shutting down instead of serving \
         a database it can no longer be trusted with. Open the binary again with \
         idb_open to continue on a fresh worker."
    ))
}

/// Leave now if this process has been retired, and return if it has not.
///
/// For the worker loop's exit path. Once the request channel is gone there is
/// nothing left to answer and no reason to wait out the grace period — and
/// returning would let the process shut down *normally*, running IDA's atexit
/// handlers over the heap this module exists to keep it out of.
pub fn exit_if_retired() {
    let Some(signal) = caught_signal() else {
        return;
    };
    #[cfg(unix)]
    exit_now(signal);
    #[cfg(not(unix))]
    let _ = signal;
}

/// Run `f` with one-shot crash isolation.
pub fn crash_guarded<T, F: FnOnce() -> Result<T, ToolError>>(
    operation: &str,
    f: F,
) -> Result<T, ToolError> {
    if let Some(signal) = caught_signal() {
        // Reachable when a request slipped past the worker loop's gate — a
        // guarded call inside another guarded call, or a handler that fans out.
        // Entering IDA again is the one thing this module exists to prevent.
        return Err(retired_error(signal));
    }
    #[cfg(unix)]
    {
        unix_guard(operation, f)
    }
    #[cfg(not(unix))]
    {
        let _ = operation;
        f()
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn crash_guard_call(
        func: extern "C" fn(*mut std::ffi::c_void),
        ctx: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;
}

#[cfg(unix)]
fn unix_guard<T, F: FnOnce() -> Result<T, ToolError>>(
    operation: &str,
    f: F,
) -> Result<T, ToolError> {
    use std::ffi::c_void;

    struct Context<T, F: FnOnce() -> Result<T, ToolError>> {
        f: Option<F>,
        result: Option<Result<T, ToolError>>,
    }

    extern "C" fn trampoline<T, F: FnOnce() -> Result<T, ToolError>>(ctx: *mut c_void) {
        let ctx = unsafe { &mut *(ctx.cast::<Context<T, F>>()) };
        if let Some(f) = ctx.f.take() {
            ctx.result = Some(f());
        }
    }

    let mut ctx = Context {
        f: Some(f),
        result: None,
    };

    let sig = unsafe {
        crash_guard_call(
            trampoline::<T, F>,
            std::ptr::from_mut(&mut ctx).cast::<c_void>(),
        )
    };

    if sig == 0 {
        return ctx.result.unwrap_or_else(|| {
            Err(ToolError::IdaError(format!(
                "{operation}: callback did not produce a result"
            )))
        });
    }

    retire(sig);
    tracing::error!(
        operation,
        signal = sig,
        "IDA SDK crashed (signal {sig} caught); retiring this worker"
    );
    Err(ToolError::WorkerRetired(format!(
        "{operation} crashed inside the IDA SDK (signal {sig}); \
         {WORKER_RETIRED_MARKER}. The jump out of the signal handler skipped the \
         destructors IDA was owed, so this worker is being terminated rather \
         than asked another question, and its database session is invalidated. \
         Open the binary again with idb_open to continue on a fresh worker. \
         This is a bug in the IDA SDK, not in ida-mcp."
    )))
}

/// Record the signal and arm the exit.
#[cfg(unix)]
fn retire(signal: i32) {
    if CAUGHT_SIGNAL.swap(signal, Ordering::AcqRel) != 0 {
        // A second catch: the first one already armed the exit, and arming
        // another thread would only shorten the grace the first one granted.
        return;
    }

    let spawned = std::thread::Builder::new()
        .name("crash-guard-exit".to_string())
        .spawn(move || {
            std::thread::sleep(RESPONSE_GRACE);
            exit_now(signal);
        });
    if spawned.is_err() {
        // No thread, no grace period. Still better than staying up: the answer
        // is lost, but the parent reads a closed transport as a dead worker,
        // which is the same conclusion by a blunter route.
        exit_now(signal);
    }
}

/// Leave without unwinding anything.
///
/// `_exit`, not `std::process::exit`: the latter runs atexit handlers and
/// destructors for statics, which is IDA's code walking IDA's heap — the heap
/// whose integrity is the reason this process is leaving. The status follows
/// the shell's `128 + signal` convention, so a caught SIGSEGV reads as the 139
/// an uncaught one would have produced.
#[cfg(unix)]
fn exit_now(signal: i32) -> ! {
    // SAFETY: `_exit` is async-signal-safe and never returns.
    unsafe { libc::_exit(128 + signal) }
}

#[cfg(test)]
mod tests {
    use super::{caught_signal, crash_guarded, retired_error, WORKER_RETIRED_MARKER};
    use crate::error::ToolError;

    #[test]
    fn a_healthy_process_runs_the_call() {
        assert!(caught_signal().is_none(), "no test may poison the process");
        let value = crash_guarded("test", || Ok::<_, ToolError>(7)).expect("guarded call");
        assert_eq!(value, 7);
    }

    /// The parent classifies by message, so the marker is part of the wire
    /// contract between a child worker and the pool that owns it.
    #[test]
    fn a_retirement_is_recognisable_after_the_trip_through_mcp() {
        let error = retired_error(11);
        let message = error.to_string();
        assert!(
            message.to_ascii_lowercase().contains(WORKER_RETIRED_MARKER),
            "{message}"
        );
        assert!(message.contains("idb_open"), "{message}");
        assert!(matches!(error, ToolError::WorkerRetired(_)));
    }
}
