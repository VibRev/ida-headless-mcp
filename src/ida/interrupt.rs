//! Reclaim the terminal signals IDA takes for itself during `init_library()`.
//!
//! # Why this exists
//!
//! `idalib::init_library()` resets the SIGINT disposition to `SIG_DFL`. Tokio
//! installs its handler — the one behind `vibrev_kit::transport::shutdown_signal`
//! — before IDA ever runs, so by the time a worker had a database open that
//! handler was already gone: Ctrl+C killed the process at exit 130 and left the
//! database on disk as unpacked `.id0`/`.id1`/`.nam`/`.til` rather than as the
//! `.i64` only a close-and-pack produces. The supervisor never loads IDA, which
//! is why the same code path has always worked there and only there.
//!
//! Taking the disposition back once is not enough: a worker initializes IDA
//! lazily, on its first request. [`arm`] is idempotent and is called again after
//! every `init_library()`.
//!
//! # Responsibilities
//!
//! - Own SIGINT/SIGTERM/SIGQUIT for a process that hosts IDA, and record which
//!   one asked it to stop.
//! - *Not* acting on that record. Packing a database is an IDA call, IDA is only
//!   ever touched from the main thread, and a signal handler may run on any
//!   thread — so [`run_ida_loop`](crate::ida::run_ida_loop) polls [`requested`]
//!   between requests and does the close-and-save itself.
//!
//! # Safety
//!
//! The handler must be async-signal-safe. It touches one atomic, calls
//! `write(2)`, and on a second signal `_exit(2)`. Nothing else — no allocation,
//! no lock, no `tracing`.

use std::sync::atomic::{AtomicI32, Ordering};

/// The signal that asked this process to stop, or 0.
static REQUESTED: AtomicI32 = AtomicI32::new(0);

/// The signal that asked this process to stop, if one has.
///
/// Cheap enough to poll; the worker loop reads it between requests. Once this
/// answers `Some` it answers `Some` forever — the process is on its way out.
pub fn requested() -> Option<i32> {
    match REQUESTED.load(Ordering::Acquire) {
        0 => None,
        signal => Some(signal),
    }
}

/// Take SIGINT/SIGTERM/SIGQUIT for this process.
///
/// Idempotent, and deliberately so: IDA reinstalls its own disposition on every
/// `init_library()`, so this has to be called again after each one. The signal
/// set matches `vibrev_kit::transport::shutdown_signal`, which the supervisor
/// keeps using — displacing tokio's handler here changes nothing there, because
/// dispositions are per-process and the supervisor is a different process.
///
/// A no-op off unix: Windows delivers console control events rather than POSIX
/// signals, and IDA does not displace what tokio installs for them.
pub fn arm() {
    #[cfg(unix)]
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
        install(signal);
    }
}

/// What a signal means, given whether one has already arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Response {
    /// First ask. Let the worker loop finish the IDA call it is inside, then
    /// close the database and exit.
    SaveAndExit,
    /// Asked twice. Waiting is the thing the second press said no to, so the
    /// unsaved analysis is the price and the person paying it chose to.
    ExitNow,
}

impl Response {
    /// Split out from the handler so the two-stage rule is testable without
    /// signalling the test process.
    fn to(previously_requested: i32) -> Self {
        match previously_requested {
            0 => Self::SaveAndExit,
            _ => Self::ExitNow,
        }
    }
}

#[cfg(unix)]
extern "C" fn handle(signal: std::ffi::c_int) {
    match Response::to(REQUESTED.swap(signal, Ordering::AcqRel)) {
        Response::SaveAndExit => announce(),
        Response::ExitNow => exit_now(signal),
    }
}

/// Say on stderr that the interrupt landed.
///
/// Without this the first Ctrl+C is invisible for as long as IDA is inside a
/// call — the worker loop cannot answer until the SDK returns, and an
/// `auto_wait` on a large binary takes minutes. The natural response to a key
/// that appeared to do nothing is to press it again, and that is exactly the
/// sequence that throws the database away.
#[cfg(unix)]
fn announce() {
    const MESSAGE: &[u8] = b"\ninterrupt: closing the open database before exit; \
        press Ctrl+C again to exit now and lose unsaved analysis\n";

    // SAFETY: `write` is async-signal-safe. `MESSAGE` is a `'static` byte
    // string, so the pointer and length are valid for the whole call. A short
    // or failed write is not worth handling on the way out, and there is no
    // async-signal-safe way to report it anyway.
    unsafe {
        libc::write(
            libc::STDERR_FILENO,
            MESSAGE.as_ptr().cast(),
            MESSAGE.len() as libc::size_t,
        );
    }
}

/// Leave without unwinding anything.
///
/// `_exit`, not `std::process::exit`: this runs from a signal handler, where
/// atexit handlers and static destructors are neither async-signal-safe nor
/// owed. The status follows the shell's `128 + signal` convention, matching
/// [`crash_guard`](crate::crash_guard).
#[cfg(unix)]
fn exit_now(signal: std::ffi::c_int) -> ! {
    // SAFETY: `_exit` is async-signal-safe and never returns.
    unsafe { libc::_exit(128 + signal) }
}

#[cfg(unix)]
fn install(signal: std::ffi::c_int) {
    // SAFETY: `action` is fully initialized before it is read — `sa_mask` by
    // `sigemptyset`, the other fields written directly — and `handle` has the
    // `extern "C" fn(c_int)` signature `sa_sigaction` is called through when
    // `SA_SIGINFO` is unset, and is async-signal-safe. The old action is
    // discarded rather than chained to: the handler being displaced is IDA's,
    // and displacing it is the point.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        // Through the fn-pointer type first: casting the function *item*
        // straight to an integer is the shape that silently produces a
        // zero-sized value's address.
        let handler: extern "C" fn(std::ffi::c_int) = handle;
        action.sa_sigaction = handler as libc::sighandler_t;
        libc::sigemptyset(&raw mut action.sa_mask);
        // SA_RESTART so the worker loop's `recv_timeout` keeps its own schedule
        // instead of coming back as an `EINTR` every caller would have to retry.
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(signal, &raw const action, std::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::{requested, Response};

    #[test]
    fn the_first_signal_asks_for_a_save() {
        assert_eq!(Response::to(0), Response::SaveAndExit);
    }

    /// The escape hatch for an interrupt that arrives while IDA is inside a
    /// call the SDK gives no way to interrupt.
    #[test]
    #[cfg(unix)]
    fn a_second_signal_gives_up_on_saving() {
        assert_eq!(Response::to(libc::SIGINT), Response::ExitNow);
        assert_eq!(Response::to(libc::SIGTERM), Response::ExitNow);
    }

    #[test]
    fn an_uninterrupted_process_reports_nothing() {
        assert!(requested().is_none(), "no test may signal the test process");
    }
}
