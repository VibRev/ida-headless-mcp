# Tests

Integration tests for ida-headless-mcp using a minimal `mini.c` fixture.

## Prerequisites

- `curl` (for HTTP tests)
- `jq` (for the stdio session test, elicitation, DSC, and crash-guard tests)

## Server binary

Every script resolves the binary under test through the same chain:

```
MCP_BIN  ->  MCP_STDIO_BIN (stdio scripts) / MCP_HTTP_BIN (HTTP scripts)
         ->  SERVER_BIN
         ->  ../target/release/ida-headless-mcp
```

`MCP_BIN` overrides every script whatever its transport; the transport-specific
names and `SERVER_BIN` are still honoured so existing recipes and shell history
keep working. Relative paths resolve against `e2e/`, which is where `just` runs
the scripts from.

The default matches `server_bin` in `justfile`, so a release build is what the
scripts expect when you run one by hand. To test a debug build, point any of the
variables at `../target/debug/ida-headless-mcp` — that is what the repo-root
`just test-*` recipes do, which is why they depend on `build` rather than
`release`.

## Build the fixture

```bash
just fixture
```

Compiles `fixtures/mini.c` to `fixtures/mini`. Most recipes that should not
wait on raw-binary auto-analysis open the already-analysed `fixtures/mini.i64`
instead (`just test-bootstrap` creates it when missing or stale).

## Run tests

```bash
just test       # Sequential supervisor stdio JSON-RPC session test
just test-supervisor-http # Multi-session supervisor HTTP smoke test
just test-supervisor-http-recovery # Kill one worker and verify isolation/reopen
just test-http  # HTTP/SSE test
just test-bootstrap # Generate fixtures/mini.i64 once via the MCP server
just test-script # IDAPython script test
just test-observability # Foreground progress/recent_operations test
just test-elicitation # open_idb auto-background elicitation test
```

`just test` drives the supervisor over stdio (`serve --mode stdio`) with a FIFO client
(`stdio_session.sh`). It waits for each JSON-RPC `id` before sending the next
request, opens `fixtures/mini.i64` with `preferred_session_id: "mini"`, and
passes `database: "mini"` on every routed tool. Address-only tools
(`stack_frame`, `xrefs_to`, `xrefs_from`) get their address from
`resolve_function` rather than a hardcoded Mach-O EA. ARM-only `patch_asm` /
ARM NOP `patch` are skipped on non-ARM processors.

`payloads/mini.jsonl` is a name-based reference of that sequence. Do not dump
it into stdin in one shot — the supervisor will run later `tools/call`s before
`idb_open` finishes.

## Clean

```bash
just clean
```
