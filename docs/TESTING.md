# Testing

## Run tests

```bash
just test         # Sequential supervisor stdio JSON-RPC session test (opens mini.i64)
just test-supervisor-catalog # Advertised catalog + resources, no IDA license needed
just test-supervisor-http    # Multi-session supervisor over HTTP
just test-supervisor-http-recovery # ... plus worker crash isolation and recovery
just test-http    # HTTP/SSE integration test
just test-modern  # MCP 2026 discover/stateless lifecycle test
just test-script  # IDAPython script execution test
just test-elicitation # open_idb auto-background elicitation test
just test-session-cancel # legacy-session cancel-on-disconnect test
just test-http-startup # HTTP bind-failure exit status (no IDA license needed)
just test-dsc /path/to/dyld_shared_cache_arm64e  # DSC loading test
just cargo-test   # Unit tests (no IDA required)
```

All integration tests require IDA Pro with a valid license, except
`just test-http-startup` and `just test-supervisor-catalog`.

The repo-root `just test-*` recipes need no build step of their own: each
depends on `build` and passes `SERVER_BIN=../target/debug/ida-headless-mcp`
explicitly. Running a script from `e2e/` by hand is the case that needs
`just release` first — a bare script falls back to
`../target/release/ida-headless-mcp`, matching the `server_bin` default in
`e2e/justfile`. Override either with `MCP_BIN`; see `e2e/README.md` for the full
resolution order.

The default entry point is the supervisor, so stdio payloads open a session
with `idb_open` (using a fixed `preferred_session_id`) and pass that ID as
`database` on every routed tool. Tests that exercise native tool behaviour
directly — `test-decompile`, `test-rebuild-idb`, `test-elicitation`,
`test-callees-indirect`, `test-dsc` — drive the `worker` subcommand, which
serves the native surface without session routing.

## What's tested

**Stdio test** (`just test`)
- Sequential JSON-RPC over a FIFO (`e2e/stdio_session.sh`): each `tools/call`
  waits for its response `id` before the next request is sent
- Opens the already-analysed `fixtures/mini.i64` (not the raw compiled `mini`)
- MCP protocol handshake (`initialize` → wait → `notifications/initialized`)
- Tool discovery (`tools/list`, `tool_catalog`, `tool_help`)
- Session lifecycle (`idb_open`, `idb_close`) and database introspection (`idb_meta`, `analysis_status`)
- Analysis tools (`list_functions`, `resolve_function`, `disasm_by_name`, `find_insns`, `find_insn_operands`)
- Editing tools (`set_comments`, `rename`; `patch` / `patch_asm` only on ARM)
- Types/stack tools (`declare_type`, `apply_types`, `infer_types`, `stack_frame`, `declare_stack`, `delete_stack`)
- Metadata tools (`segments`, `strings`, `imports`, `exports`, `structs`, `xrefs_to_field`, `search_structs`)
- Address-only tools (`stack_frame`, `xrefs_to`, `xrefs_from`) take the address
  returned by `resolve_function`, not a hardcoded EA
- Each request is asserted individually; ARM-only or fixture-missing failures
  are named expected skips, not a global `isError` budget

**HTTP test** (`just test-http`)
- Streamable HTTP transport with SSE
- `tools/list` returns the full tool list
- Database operations work over HTTP (`open_idb`, `list_functions`, `close_idb` with close_token)

**MCP 2026 test** (`just test-modern`)
- Exercises `server/discover`, `tools/list`, and `tools/call` over stdio
- Rejects MCP 2026 requests with incomplete required request metadata
- Exercises the same lifecycle over sessionless HTTP and verifies that no
  legacy session ID is created
- Verifies a legacy stdio task remains visible on the same connection when one
  request carries full routing metadata and the next omits it

**Script test** (`just test-script`)
- Opens a binary, then runs inline Python via `run_script`
- Verifies stdout/stderr capture
- Verifies Python error reporting (division by zero)
- Verifies file-based script execution (`.py` file path)

**Elicitation test** (`just test-elicitation`)
- Creates a sparse Mach-O fixture just over 50 MiB
- Verifies `open_idb(auto_analyse=true)` silently routes analysis to a background task when the client has no elicitation capability
- Verifies an elicitation-capable client receives `elicitation/create`, accepts it, and gets `analysis_background=true` plus a pollable `analysis_task_id`
- Verifies MCP `2026-07-28` returns `input_required`, accepts the echoed
  integrity-protected `requestState` plus `inputResponses`, and completes the
  retried tool call

**Startup-failure test** (`just test-http-startup`)
- Squats a port with a supervisor parent (binds in ms, takes no IDA license),
  then starts `serve-http` against it with default flags and again with
  explicit `--max-workers`
- Asserts each start exits nonzero, does not wedge (watchdog SIGKILL would show
  as 137), and never logs "Initializing IDA library" — a start that cannot bind
  must not take an IDA licence
- Asserts the failing start never logs a clean stop it didn't achieve
- Needs no IDA license, database, or fixture

**Session-cancel test** (`just test-session-cancel`)
- Over HTTP: a legacy session starts a slow foreground `open_idb`
  (observed via `recent_operations`), queues a background `analyze_funcs`
  behind it, then DELETEs the session
- Verifies a second legacy session cannot reuse the deduplicated task ID or
  poll the first session's task
- Verifies the server records owner cancellation only after the background
  operation settles and never records successful completion for that task

**DSC test** (`just test-dsc <path>`)
- Requires a real `dyld_shared_cache_arm64e` file
- Tests the native IDA 9.4 `dscu` path and legacy generated-`.i64` fallback where available
- Polls `task_status` until completion
- Verifies the database is usable after loading (`list_functions`)

**Unit tests** (`just cargo-test`)
- `src/dsc.rs` — file type strings, idat args, script generation, Python string escaping
- `src/server/task.rs` — task registry lifecycle, owner-scoped access and
  deduplication, bounded admission, cancellation, and ISO timestamps

## Test fixture

Tests use `e2e/fixtures/mini.c`, a minimal C program. `just fixture` compiles
it to `e2e/fixtures/mini` (ELF on Linux, Mach-O on macOS). The default stdio
session test opens the already-analysed `e2e/fixtures/mini.i64` so addresses
and types stay stable and the client does not wait on raw auto-analysis.
`just test-bootstrap` rebuilds that IDB when it is missing or older than
`mini.c`. Other recipes that exercise native `open_idb` on a raw binary still
compile and open `fixtures/mini`.
