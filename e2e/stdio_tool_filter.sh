#!/usr/bin/env bash
# Server-side tool filtering (Phase 2a):
#   1. tools/list reflects --toolsets/--tools/--exclude-tools at the protocol level
#   2. calling a filter-disabled tool returns an "invalid_params"-flavored error
#   3. env vars mirror flags
#   4. flags override env vars
#
# No IDA database required — exercises the dispatch surface only.
set -euo pipefail

BIN="${MCP_BIN:-${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"

[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

work="$(mktemp -d)"
fifo="$work/in.fifo"
log="$work/server.log"

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "${pid:-}" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

start_server() {
  # Args are extra flags passed to `$BIN serve`. Caller sets any env vars
  # inline before the function call (bash inherits them into the spawned
  # process automatically).
  cleanup_stale_pid
  pid=
  rm -f "$fifo"
  mkfifo "$fifo"
  : > "$log"
  "$BIN" serve "$@" < "$fifo" > "$log" 2>&1 &
  pid=$!
  exec 3>"$fifo"
}

cleanup_stale_pid() {
  if [[ -n "${pid:-}" ]]; then
    exec 3>&- 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pid=
  fi
}

send() { echo "$1" >&3; }

wait_response() {
  local target_id="$1" timeout="${2:-15}" elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    local line
    line=$(grep -m1 "\"id\":${target_id}[,}]" "$log" 2>/dev/null | grep '"jsonrpc"' || true)
    [[ -n "$line" ]] && { echo "$line"; return 0; }
    sleep 1; elapsed=$((elapsed + 1))
  done
  echo "timeout id=$target_id" >&2
  echo "--- server log ---" >&2; cat "$log" >&2
  return 1
}

initialize() {
  send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"filter-test","version":"0.1"},"capabilities":{}}}'
  send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
  wait_response 1 10 >/dev/null
}

# --- Phase A: --toolsets=core --exclude-tools=analysis_status via flags ---
echo "── Phase A: flag-based filter (toolsets=core, exclude=analysis_status) ──"
start_server --toolsets=core --exclude-tools=analysis_status
initialize

send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)

echo "$names" | grep -q '^idb_open$' || { echo "FAIL: idb_open (core) missing"; exit 1; }
echo "$names" | grep -q '^idb_list$' || { echo "FAIL: idb_list (core) missing"; exit 1; }
if echo "$names" | grep -q '^analysis_status$'; then
  echo "FAIL: analysis_status should be filtered out" >&2; exit 1
fi
if echo "$names" | grep -q '^decompile$'; then
  echo "FAIL: decompile (decompile category) leaked into core-only" >&2; exit 1
fi
echo "   ✓ tools/list narrowed to core minus analysis_status"

# Calling a filter-disabled tool must return a JSON-RPC error ("invalid_params"
# message field), not a regular CallToolResult.
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analysis_status","arguments":{}}}'
deny_resp=$(wait_response 3 10)
err_msg=$(echo "$deny_resp" | jq -r '.error.message // empty')
[[ -n "$err_msg" ]] || { echo "FAIL: expected JSON-RPC error for disabled tool, got $deny_resp" >&2; exit 1; }
echo "$err_msg" | grep -qi "disabled by current filter" || {
  echo "FAIL: error message should mention 'disabled by current filter'; got: $err_msg" >&2
  exit 1
}
echo "   ✓ analysis_status returned disabled-tool error"

# --- Phase B: env-var mirror (no flags, only IDA_MCP_*) ---
echo "── Phase B: env-var mirror (IDA_MCP_TOOLSETS=core, IDA_MCP_EXCLUDE_TOOLS=analysis_status) ──"
IDA_MCP_TOOLSETS=core IDA_MCP_EXCLUDE_TOOLS=analysis_status start_server
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^idb_open$' || { echo "FAIL: env-var idb_open missing"; exit 1; }
if echo "$names" | grep -q '^analysis_status$'; then
  echo "FAIL: env-var IDA_MCP_EXCLUDE_TOOLS should drop analysis_status" >&2; exit 1
fi
echo "   ✓ env vars mirror flags"

# --- Phase B2: env-var mirror also applies to the default stdio command ---
# Most installed-client configs run `ida-headless-mcp` directly, relying on
# the default stdio server path instead of spelling out an explicit `serve`.
echo "── Phase B2: env-var mirror on default command (no explicit serve) ──"
cleanup_stale_pid
pid=
rm -f "$fifo"
mkfifo "$fifo"
: > "$log"
IDA_MCP_TOOLSETS=decompile "$BIN" < "$fifo" > "$log" 2>&1 &
pid=$!
exec 3>"$fifo"
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^decompile$' || { echo "FAIL: default-command env should expose decompile"; exit 1; }
# The session primitives survive every toolset (vibrev-kit calls them
# `essential`). A server filtered down to `decompile` with no way to open a
# database would advertise tools that can only answer "no database open", so
# the filter never drops them.
echo "$names" | grep -q '^idb_open$' || {
  echo "FAIL: session primitives must survive any toolset" >&2
  exit 1
}
echo "   ✓ env vars apply without explicit serve"

# --- Phase B3: filter FLAGS also apply on the default stdio command ---
# Regression for https://github.com/blacktop/ida-mcp-rs/...: clap rejected
# `--toolsets=core` because the flag was only defined on serve/serve-http
# subcommands. With the global=true fix on Cli, this should now parse and run.
echo "── Phase B3: filter flag on default command (no explicit serve) ──"
cleanup_stale_pid
pid=
rm -f "$fifo"
mkfifo "$fifo"
: > "$log"
"$BIN" --toolsets=core --exclude-tools=analysis_status < "$fifo" > "$log" 2>&1 &
pid=$!
exec 3>"$fifo"
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^idb_open$' || { echo "FAIL: default-command flag should expose idb_open (core)"; exit 1; }
if echo "$names" | grep -q '^analysis_status$'; then
  echo "FAIL: default-command --exclude-tools should drop analysis_status" >&2
  exit 1
fi
if echo "$names" | grep -q '^decompile$'; then
  echo "FAIL: default-command --toolsets=core should not expose decompile" >&2
  exit 1
fi
echo "   ✓ filter flags apply without explicit serve"

# --- Phase B4: bool-like env values for IDA_MCP_READ_ONLY ---
echo "── Phase B4: IDA_MCP_READ_ONLY accepts 1/0 env values ──"
IDA_MCP_READ_ONLY=1 start_server
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^idb_open$' || { echo "FAIL: read-only env should keep idb_open"; exit 1; }
echo "$names" | grep -q '^decompile$' || { echo "FAIL: read-only env should keep decompile"; exit 1; }
if echo "$names" | grep -q '^patch$'; then
  echo "FAIL: IDA_MCP_READ_ONLY=1 should drop patch" >&2
  exit 1
fi
if echo "$names" | grep -q '^rename$'; then
  echo "FAIL: IDA_MCP_READ_ONLY=1 should drop rename" >&2
  exit 1
fi
echo "$names" | grep -q '^analysis_status$' || {
  echo "FAIL: read-only should keep the read-only analysis_status" >&2
  exit 1
}

IDA_MCP_READ_ONLY=0 start_server
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^patch$' || { echo "FAIL: IDA_MCP_READ_ONLY=0 should leave patch enabled"; exit 1; }
echo "   ✓ IDA_MCP_READ_ONLY accepts 1/0"

# --- Phase C: flags override env vars ---
# Env says 'core'; the flag forces the smaller 'decompile' set.
# The decompile category should win and core-only tools should NOT appear.
echo "── Phase C: --toolsets=decompile flag overrides IDA_MCP_TOOLSETS=core ──"
IDA_MCP_TOOLSETS=core start_server --toolsets=decompile
initialize
send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
list_resp=$(wait_response 2 10)
names=$(echo "$list_resp" | jq -r '.result.tools[].name' | sort)
echo "$names" | grep -q '^decompile$' || { echo "FAIL: decompile category should be active"; exit 1; }
# `idb_open` cannot be the witness that core lost: session primitives are
# essential and appear under every toolset, so it is present either way.
# `analysis_status` is in core and not in decompile, which makes it the witness
# that actually distinguishes the two.
if echo "$names" | grep -q '^analysis_status$'; then
  echo "FAIL: --toolsets=decompile flag should override IDA_MCP_TOOLSETS=core; analysis_status leaked" >&2
  exit 1
fi
echo "   ✓ flags override env vars"

# --- Phase D: startup must reject unknown toolset ---
echo "── Phase D: startup rejects unknown toolset name ──"
if "$BIN" serve --toolsets=not_a_real_category < /dev/null > "$work/bad.log" 2>&1; then
  echo "FAIL: startup should reject unknown toolset" >&2
  cat "$work/bad.log" >&2
  exit 1
fi
# vibrev-kit owns this message, not this repo: it says "unknown tool category"
# followed by the list of valid ones, so the assertion tracks the kit's wording.
grep -q "unknown tool category" "$work/bad.log" || {
  echo "FAIL: error should mention 'unknown tool category'; got: $(cat "$work/bad.log")" >&2
  exit 1
}
echo "   ✓ unknown toolset rejected at startup"

echo "✅ stdio tool-filter test passed"
