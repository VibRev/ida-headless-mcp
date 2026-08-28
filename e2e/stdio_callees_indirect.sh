#!/usr/bin/env bash
# Regression test for PR #20's callees fallback (issue: indirect-call
# operands like Mem/Displ also expose op.address(), so the unfiltered
# fallback invented bogus callee nodes for `call qword ptr [rip+x]` and
# similar). Verifies that:
#   1. open_idb on a raw binary with a bundle-id-style filename produces
#      the path with `.i64` appended (not replacing the trailing dotted
#      segment) — covers PR #20's path-naming fix.
#   2. callees() on a function with an indirect call returns the direct
#      callee but not the indirect-call's load-site address — covers the
#      operand-kind filter added in the PR #20 fixup.
# These payloads exercise the native tool surface (open_idb / close_idb and
# friends). The default entry point is the supervisor, which owns database
# lifecycle through idb_open / idb_close, so drive the worker subcommand --
# it serves the native surface directly.

set -euo pipefail

BIN="${MCP_BIN:-${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
FIXTURE_SRC="${FIXTURE_SRC:-fixtures/indirect.c}"
CC_BIN="${CC:-cc}"

# Use a bundle-id-style filename so this also exercises PR #20's path fix.
work_dir="$(mktemp -d)"
fixture="$work_dir/com.apple.driver.testfix"
expected_i64="$fixture.i64"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    # Close FIFO writer FD so the server sees EOF on stdin and exits.
    exec 3>&- 2>/dev/null || true
    # Bounded wait: poll for exit, then escalate TERM → KILL.
    local waited=0
    while kill -0 "$server_pid" 2>/dev/null && (( waited < 5 )); do
      sleep 1; waited=$((waited + 1))
    done
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -TERM "$server_pid" 2>/dev/null || true
      waited=0
      while kill -0 "$server_pid" 2>/dev/null && (( waited < 5 )); do
        sleep 1; waited=$((waited + 1))
      done
    fi
    if kill -0 "$server_pid" 2>/dev/null; then
      echo "   cleanup: server $server_pid did not exit after EOF+TERM, sending KILL" >&2
      kill -KILL "$server_pid" 2>/dev/null || true
    fi
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work_dir"
  if [[ -n "${fifo_in:-}" ]]; then
    rm -f "$fifo_in"
  fi
}
trap cleanup EXIT INT TERM

[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v "$CC_BIN" >/dev/null || { echo "$CC_BIN required to build fixture" >&2; exit 1; }

"$CC_BIN" -O0 -g -fno-omit-frame-pointer -o "$fixture" "$FIXTURE_SRC"

fifo_in="$(mktemp -u).fifo"
mkfifo "$fifo_in"
log="$work_dir/server.log"

"$BIN" worker < "$fifo_in" > "$log" 2>&1 &
server_pid=$!
exec 3>"$fifo_in"

send() { echo "$1" >&3; }

wait_response() {
  local target_id="$1" timeout="${2:-90}" elapsed=0
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

text() { jq -r '.result.content[0].text // empty'; }

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"callees-indirect","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'
wait_response 1 10 >/dev/null
echo "   initialized"

# Phase 1: open the bundle-id-named raw binary
payload=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"open_idb","arguments":{"path":"%s","auto_analyse":true}}}' "$fixture")
send "$payload"
open_text=$(wait_response 2 120 | text)
i64_path=$(echo "$open_text" | jq -r '.path // empty')

[[ "$i64_path" == "$expected_i64" ]] || {
  echo "FAIL: open_idb returned path '$i64_path', expected '$expected_i64'" >&2
  echo "$open_text" >&2
  exit 1
}
echo "   ✓ Bundle-id name preserved: $i64_path"

# Phase 2: resolve the function and pull its callees
send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resolve_function","arguments":{"name":"interesting_function"}}}'
addr=$(wait_response 3 30 | text | jq -r '.address // empty')
[[ -n "$addr" && "$addr" != "null" ]] || { echo "FAIL: resolve_function returned no address" >&2; exit 1; }
echo "   interesting_function @ $addr"

send "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"callees\",\"arguments\":{\"addr\":\"$addr\"}}}"
callees_text=$(wait_response 4 30 | text)

# Must include direct_callee
echo "$callees_text" | jq -e '.[] | select(.name | test("direct_callee"))' >/dev/null || {
  echo "FAIL: callees missing direct_callee" >&2
  echo "$callees_text" >&2
  exit 1
}
echo "   ✓ direct_callee present"

# Must NOT contain any callee whose address belongs to the same fixture's
# data segment (i.e. the BSS slot that holds `fptr`). We approximate this
# by rejecting any callee with size==0 AND a name that doesn't start with
# `direct_callee` or known function naming. The pre-fix fallback would
# have produced an entry with size==0 pointing at the fptr load address.
bogus=$(echo "$callees_text" | jq -r '
  .[] | select(.name | test("direct_callee") | not) | .address
')
if [[ -n "$bogus" ]]; then
  echo "FAIL: callees included unexpected non-direct-callee entries:" >&2
  echo "$bogus" | sed 's/^/  /' >&2
  echo "full callees response:" >&2
  echo "$callees_text" >&2
  exit 1
fi
echo "   ✓ No bogus callee from indirect call"

# Phase 3: clean close so .i64 is flushed
send '{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"close_idb","arguments":{}}}'
wait_response 99 10 >/dev/null

[[ -f "$expected_i64" ]] || { echo "FAIL: $expected_i64 not on disk after close" >&2; exit 1; }
echo "   ✓ .i64 flushed at expected path"

echo "✅ callees-indirect regression passed"
