# Transports

One command, two transports: `serve --mode http` (the default) and
`serve --mode stdio`. Both run the same supervisor over the same pool of child
`worker` processes; only the framing differs. Flags that describe the pool are
shared; flags that describe a listener are refused under `--mode stdio` rather
than silently ignored.

## Stdio

- Single-client, simplest setup.
- Use with CLI agents that launch a child process — this is what an installed
  MCP client's config should name.

```bash
./target/release/ida-headless-mcp serve --mode stdio
```

A bare `ida-headless-mcp` does not mean this. It serves HTTP on
`127.0.0.1:8765`, so a client that spawns it and waits on the pipe will wait
forever.

### Progress observability

The server does not emit MCP `notifications/progress` messages. On stdio they
race with the response on fast tools (under ~100 ms): Node-based clients
(e.g. Claude Code) deliver coalesced messages in a single `data` event and
process the response — which retires the `progressToken` — before the
notification handlers run, dropping the transport with "unknown progress
token". Phase progress is recorded server-side instead and surfaced via the
`recent_operations` tool. Long-running work (e.g. `analyze_funcs`) should be
launched with the tool's background option and polled through `task_status`.
Clients declaring the MCP Tasks extension also receive native task handles for
background work. (`open_dsc` is worker-local — it is not on the supervisor
catalog that stdio and HTTP serve; reach it through the `worker` subcommand.)

## Streamable HTTP (multi-client transport)

- The default transport: `serve`, `serve --mode http` and a bare
  `ida-headless-mcp` all land here.
- Supports multiple clients over HTTP.
- The supervisor always runs over a pool of child `worker` processes. There is
  no in-process HTTP topology: the command never enters an IDA worker loop
  itself, so a failed bind cannot strand a licence.
- Each open database leases its own child worker, so different sessions can
  analyse different IDBs concurrently. `--max-workers` (default 4) caps how
  many exist at once.
- SSE is used for streaming responses within this transport.
- **Every request needs a bearer token.** See [Authentication](#authentication)
  below — there is no flag that turns it off.
- The server requires the bearer token on every request.

```bash
# The default: no arguments needed for a loopback listener
./target/release/ida-headless-mcp

# Same thing, spelled out
./target/release/ida-headless-mcp serve --mode http --bind 127.0.0.1:8765

# Concurrent multi-IDB sessions
./target/release/ida-headless-mcp serve \
  --bind 127.0.0.1:8765 \
  --max-workers 4 \
  --min-workers 1

# Exposing on a LAN by IP address
./target/release/ida-headless-mcp serve \
  --bind 0.0.0.0:8765

# Exposing on a LAN by DNS name
./target/release/ida-headless-mcp serve \
  --bind 0.0.0.0:8765 \
  --allow-host ida-box.local
```

Options:
- `--stateless`: force POST-only mode for legacy protocols. MCP `2026-07-28`
  is always sessionless, with or without this flag.
- `--json-response`: prefer `application/json` over SSE framing for
  sessionless responses (`--stateless` mode and all MCP `2026-07-28`
  requests)
- `--max-request-body-mib`: maximum accepted request body (default 16, range
  1-1024). Bulk `patch` sends binary as hex at ~2x the raw size and
  `run_script` sends whole sources, so rmcp's 4 MiB default is too small. The
  buffer grows before the token is checked, so an unauthenticated caller can
  still make each in-flight request retain up to this much; raise it
  deliberately. Over-cap requests get a transport-level HTTP 413 that names the
  limit, outside the JSON-RPC envelope.
- `--token-file`: path to the shared bearer-token file (default
  `~/.vibrev/token`, env `IDA_MCP_TOKEN_FILE`). See [Authentication](#authentication).
- `--allow-host`: comma-separated `Host` allowlist for DNS names or alternate
  authorities. Defaults to `*`, which disables the check; naming any host
  enables it, and IP literals reachable through the bind address are then
  allowed automatically
- `--sse-keep-alive-secs`: keep-alive interval (0 disables)
- `--session-keep-alive-secs`: HTTP session inactivity timeout (default 1800s;
  0 disables). This is the fallback reclaim for POST-only clients — SSE clients
  are reclaimed faster via `--worker-disconnect-grace-secs`.
The four below describe the worker pool, so they apply to **both** transports.

- `--max-workers`: maximum child worker processes, one per open database
  (default 4); `1` still uses a child process, it just serializes every session
  behind that one
- `--min-workers`: idle child workers to keep warm (default 0)
- `--worker-idle-timeout-secs`: seconds before an idle worker process is
  reaped (default 300s; 0 disables)
- `--worker-op-timeout-secs`: per-child operation watchdog (default 1800s).
  The parent kills a child that exceeds it; this guards against wedged
  workers, not normal long analysis.

HTTP only — there is no stream to lose on stdio, so `--mode stdio` refuses it:

- `--worker-disconnect-grace-secs`: reconnect grace before a session is closed
  after the client drops its standalone SSE stream (default 2s)

## Authentication

HTTP — which is what `serve` does unless told otherwise — requires
`Authorization: Bearer <token>` on every request. There is no flag to disable
it. `serve --mode stdio` is unaffected: the client spawns the process directly,
so there is no listener to reach and no token involved.

**Why unconditional, even on loopback.** What the endpoint exposes is opening
any file on the host as a database — reading arbitrary files is what this tool
does — plus arbitrary code execution once `--unsafe` is on. `Host` validation
can stop a browser tab from reaching in by DNS rebinding, but it stops
nothing that can open a socket, and every local process can. That is also why
the `Host` check is not on by default: it defends against one narrow attack the
token already covers, at the cost of rejecting ordinary proxy setups. On a multi-user
machine loopback is not a boundary.

**Where the token comes from.** `~/.vibrev/token`, created on first use with
mode `0600` (`O_CREAT|O_EXCL`, so two processes racing to create it cannot end
up with two different tokens), inside a `0700` directory. It is generated once
and reused: a token that changed per process would invalidate every installed
client config on restart. Point `--token-file` (or `IDA_MCP_TOKEN_FILE`)
somewhere else for a throwaway instance or a test.

The file is a list, one token per line, `#` comments and blank lines ignored.
The first entry is the current token; **every listed entry is accepted**. That
is what lets a rotation keep the outgoing token valid until each client config
has actually been rewritten, so a rotation that fails halfway through leaves no
client stranded. To rotate by hand: stop the server, put the new token on the
first line and leave the old one on the second, restart, update your clients,
then delete the old line and restart again.

**Configuring a client.** The HTTP listener prints a paste-able snippet on startup.
The token itself is only spelled out when stderr is a terminal; redirected to a
log file it is elided, and the banner tells you how to read it:

```jsonc
"ida-headless-mcp": {
  "type": "http",
  "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer vbr_…" }
}
```

```bash
head -n1 ~/.vibrev/token   # the current token
```

Never put this entry in a version-controlled config (`.mcp.json`,
`.vscode/mcp.json`): the URL is a local port and the token is a local
credential, so the entry cannot work for anyone else, and committing it puts
the credential in your history.

**What a rejected request looks like.** `401` with a `WWW-Authenticate: Bearer`
challenge for a missing or wrong token — a credential *would* change the
answer, which is what separates 401 from the `403` the `Host` policy
returns. The response body never says anything about the accepted token.
Coverage is router-wide: `/mcp`, `/sse`, `/output/` and any unrouted path all
sit behind the same check, so a cached tool result cannot be fetched without
the token even though its id was handed out over an authenticated session.
Nothing is exempt — there is no unauthenticated health endpoint to probe.

## Protocol lifecycle

The server supports the legacy `initialize` lifecycle from `2024-11-05`
through `2025-11-25`. MCP `2026-07-28` uses `server/discover` and per-request
metadata instead. Both transports negotiate against the same version list, so
a client reaches the same answer over stdio and over HTTP; neither face clips
the sessionless 2026 lifecycle off the end. HTTP shares task, operation, and
MRTR state across the fresh handler instances created for sessionless requests.
Background tasks (DSC loading, auto-analysis)
spawned by a legacy session are cancelled when that session closes; tasks
spawned by sessionless MCP 2026 requests outlive their request and run until
completion, `tasks/cancel`, or server shutdown. Legacy task IDs are scoped to
their owning session for deduplication, polling, updates, and cancellation; a
different legacy session receives the same response as it would for an unknown
ID. Stdio task ownership remains connection-scoped even if request metadata is
present on only some messages. Sessionless HTTP requests share the runtime task
owner because MCP 2026 provides no stable session identity across requests.
Under `--stateless`, every HTTP request is served by a per-request handler
regardless of protocol version, so legacy requests there also use the shared
runtime owner and lifetime — their background tasks survive the request and
stay pollable across requests. Within that shared owner, the task ID is the
only access credential: IDs carry full per-task randomness and should be
treated like a `close_token`, not logged or shared.

Task cancellation is cooperative. A cancellation request signals the active
operation, but the task remains `working` while an uncancellable synchronous
IDA call settles. Only then does the server publish the terminal `cancelled`
state, so a terminal task never has IDA work still running behind it. The
legacy idat subprocess is the exception: cancellation kills it, reaps it, and
removes its partial database output before publishing `cancelled`, so a later
`open_dsc` cannot reuse a half-written database.

HTTP is not limited to the legacy versions. A supervisor request names its
database with the `database` argument returned by `idb_open`, so routing does
not need the connection to carry identity — which is exactly what the
sessionless 2026 lifecycle asks for. Worker affinity follows the `database`
handle rather than an HTTP session, so it survives across sessionless
requests.

## Concurrency model

IDA requires main-thread access, and one IDA process can own only one active
database at a time. Multi-database support is therefore process isolation, not
IDB switching: each opened database leases a child `ida-headless-mcp worker`
process, so different sessions can own different IDBs concurrently until
`idb_close`, HTTP `DELETE`, session timeout, or server shutdown. With
`--max-workers 1` there is still a child process — every session just
serializes behind that one. `idb_close` releases the lease immediately; the
child process can remain idle for reuse until `--worker-idle-timeout-secs`
elapses. If an SSE-capable client exits without sending `idb_close` or HTTP
`DELETE`, the abandoned session is closed when its standalone SSE stream
disconnects and the reconnect grace elapses. POST-only clients have no
persistent stream to observe, so their orphaned sessions are reclaimed by
`--session-keep-alive-secs`.

## Logging and sensitive payloads

Tool spans record only sanitized fields (paths, sizes, booleans) — never
ownership tokens, MRTR state, elicitation answers, script sources, patch
bytes, or comment/rename text.

Scope the filter when troubleshooting: `RUST_LOG=ida_mcp=debug`. A bare
`RUST_LOG=debug` also enables the MCP SDK's own request logging, which writes
whole JSON-RPC envelopes — including tool arguments — to stderr.

## Known limitations

- **`close_token` is worker-local.** The supervisor closes a session by the
  `database` ID that `idb_open` returned — `idb_close` takes `database` and
  `save`, and there is no token to lose. The `close_token` / `force=true`
  recovery path belongs to the worker-local `open_idb` / `close_idb` pair, so
  it is not reachable over HTTP.
- **Operation history is per database, not per client.** `recent_operations`
  is routed to the worker that owns the `database` it names, so its history
  covers every client that has touched that database (including target file
  paths) and reports one active operation at a time for it.
- **No task enumeration.** The MCP tasks extension (SEP-2663) defines
  `tasks/get`, `tasks/update`, and `tasks/cancel` only. Clients that used the
  experimental `tasks/list` / `tasks/result` methods from pre-3.0 rmcp SDKs
  must retain the `task_id` returned by the spawning tool call; a task whose
  id is lost can only be waited out.
- **Bounded task retention.** The server retains up to 256 running and terminal
  tasks. Terminal results normally remain available for the advertised 24-hour
  TTL, but the TTL is an upper bound, not a guarantee: when the registry hits
  its cap, admitting new background work reclaims the least recently updated
  terminal results early. Running tasks are never reclaimed, so a registry
  full of in-flight work still rejects new background work until something
  settles. Fetch results promptly rather than relying on the full TTL.

## Shutdown

The server listens for SIGINT/SIGTERM/SIGQUIT and closes every open database —
packing it to its `.i64` — before it exits. Ctrl+C is the ordinary way to stop
it; the databases are saved, not discarded.

Workers run in their own process group, so a terminal Ctrl+C reaches the
supervisor alone and the supervisor closes the databases in order. A worker
signalled directly saves its own database and exits `130`.

**Interrupting a busy worker.** The IDA SDK is single-threaded and blocking, so
an interrupt that lands during a long call — `auto_wait` on a large binary,
a slow decompilation — cannot be acted on until that call returns. The first
Ctrl+C prints

```
interrupt: closing the open database before exit; press Ctrl+C again to exit now and lose unsaved analysis
```

and waits. **A second Ctrl+C exits immediately and the analysis since the last
save is lost** — that is the escape hatch, not the default, so do not use it to
hurry a shutdown that is already under way.
