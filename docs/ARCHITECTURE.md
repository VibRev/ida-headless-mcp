# Architecture

`ida-headless-mcp` is split into two runtime roles implemented by the same
binary:

- The supervisor owns MCP transports, the advertised tool catalog, output caching,
  and the mapping from public `database` session IDs to workers.
- A worker loads exactly one matching IDA runtime and serializes every SDK call
  on IDA's main thread.

One IDA process cannot safely own multiple active databases. Multi-session
support therefore uses process isolation rather than switching a global IDB in
one process.

```mermaid
flowchart LR
    Client[MCPClient] -->|stdio_or_HTTP| Supervisor[RustSupervisor]
    Supervisor --> Registry[SessionRegistry]
    Registry -->|database_A| WorkerA[IDAWorkerA]
    Registry -->|database_B| WorkerB[IDAWorkerB]
    WorkerA --> IDBA[IDB_A]
    WorkerB --> IDBB[IDB_B]
```

## Session invariants

- `idb_open` returns an opaque random session ID. A path is never accepted as
  a substitute for that ID.
- Every non-management tool requires `database`.
- The same canonical database path is adopted instead of opened twice.
- A worker is never shared by two database sessions.
- `idb_close` optionally saves before releasing the worker and file lock.
- Worker failure invalidates only its own session.
- Idle workers have a bounded lifetime; the default is 600 seconds. A session is
  reaped only if it is still idle at the moment the close commits, so a call
  accepted while the reaper was deciding keeps its session.

## Crashes

`src/crash_guard.rs` catches SIGSEGV and SIGBUS raised inside an SDK call and
turns them into an answer. That answer is a diagnosis, not a recovery: the jump
out of the signal handler skipped the destructors IDA was owed, so the process
is retired rather than reused.

- The worker refuses every later request, naming the signal, and exits with
  `128 + signal` after a short grace period for the answer to be written. It
  does not close the database first — dropping an open `IDB` is IDA code, and
  the heap is what has just become untrustworthy. The file lock is released,
  and the parent (or the stale-lock sweep) removes what the exit left behind.
- The supervisor recognises that answer, retires that child, invalidates only
  the session that was using it, and replenishes the pool. Other sessions are
  unaffected; `idb_open` starts a fresh worker.
- Run as a bare `worker` there is no supervisor to do any of that, so the
  process simply exits and its client must start a new one.

macOS delivers `EXC_BAD_ACCESS` as a Mach exception, which bypasses the Unix
signal handler once IDA has installed its own — crashes inside IDA are still
caught there, but a synthetic `raise_signal` is not, which is why the
signal-path e2e tests are Linux-only.

## SDK versions

Builds select exactly one of `ida-92`, `ida-93`, or `ida-94`. The selected
feature pins the matching `idalib` branch and the executable checks the loaded
IDA minor before opening a database. Runtime libraries and SDK files are not
part of release archives.

Versioning is three independent numbers, not one:

- Crate `version` (currently `0.1.0`) is the product version.
- `COMPILED_IDA_VERSION` is the IDA minor this binary was linked against.
- Release tags are `v${product version}` (for example `v0.1.0`), not `v9.4.x`.

`idalib` supplies the main safe Rust API. Operations that it does not expose
yet—database saves, code/function definition, operand display types, enum and
variable edits, decompiler cache invalidation, and signature operand masks—go
through `src/ida_sdk_bridge.cpp`. The bridge exports a narrow C ABI, is compiled
against the selected SDK, and is exercised by all three SDK-manifest builds.

## Compatibility boundary

The public contract is pinned to `mrexodia/ida-pro-mcp` commit
`0b5f7ae4026d3c770b190ca93c0692d1b0ceab22`. Debugger and GUI discovery tools
are intentionally outside the headless boundary. See `MIGRATION.md`.
