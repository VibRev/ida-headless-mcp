/*
 * Crash isolation for IDA SDK FFI calls.
 *
 * Catches SIGSEGV/SIGBUS during a callback via sigsetjmp/siglongjmp
 * and returns the signal number instead of killing the process.
 */

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>

static __thread sigjmp_buf guard_jmp;
static __thread volatile sig_atomic_t guard_active;

static void guard_handler(int sig) {
    if (guard_active) {
        guard_active = 0;
        siglongjmp(guard_jmp, sig);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

/*
 * Call `func(ctx)` with crash protection.
 * Returns 0 on success, or the caught signal number (e.g. 11 for SIGSEGV).
 */
int crash_guard_call(void (*func)(void *ctx), void *ctx) {
    struct sigaction sa, prev_segv, prev_bus;
    sa.sa_handler = guard_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGSEGV, &sa, &prev_segv);
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, &prev_bus);
#endif

    int sig = sigsetjmp(guard_jmp, 1);
    if (sig == 0) {
        guard_active = 1;
        func(ctx);
        guard_active = 0;
    }

    sigaction(SIGSEGV, &prev_segv, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &prev_bus, NULL);
#endif

    return sig;
}
