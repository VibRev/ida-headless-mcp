#!/usr/bin/env bash
# A SIGSEGV that `crash_guard` catches must retire the worker that took it.
#
# The catch itself is covered by `just test-crash-guard`, which drives a bare
# `worker`. This is the other half: under the supervisor, a caught signal has
# to invalidate exactly one session, leave every other session working, retire
# the child rather than reuse it, and still allow a fresh open afterwards.
#
# Linux only. macOS delivers EXC_BAD_ACCESS as a Mach exception, which bypasses
# the Unix handler the guard installs once IDA has registered its own — crashes
# inside IDA are still caught there, but this synthetic `raise_signal` is not.
set -euo pipefail

PORT="${PORT:-8767}"
BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
url="http://127.0.0.1:${PORT}/mcp"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Supervisor guarded-signal test skipped (signal-delivered SIGSEGV is Linux-only)"
  exit 0
fi

for command in curl jq; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "$command is required" >&2
    exit 1
  }
done
[[ -x "$BIN" ]] || {
  echo "missing server binary: $BIN" >&2
  exit 1
}

tmpdir="$(mktemp -d)"
server_log="$tmpdir/server.log"

# Copies, not the fixture itself: two sessions must be two databases, and the
# crash leaves its own copy behind unclosed.
case "$IDB_PATH" in
*.i64) fixture_ext=".i64" ;;
*.idb) fixture_ext=".idb" ;;
*) fixture_ext="" ;;
esac
crashed_binary="$tmpdir/mini-crashed${fixture_ext}"
survivor_binary="$tmpdir/mini-survivor${fixture_ext}"
fresh_binary="$tmpdir/mini-fresh${fixture_ext}"
cp "$IDB_PATH" "$crashed_binary"
cp "$IDB_PATH" "$survivor_binary"
cp "$IDB_PATH" "$fresh_binary"

# A throwaway token file: a test must not create or read the operator's
# long-lived ~/.vibrev/token.
token_file="$tmpdir/token"
token="vbr_crash_signal_test_$$"
printf '%s\n' "$token" >"$token_file"
chmod 600 "$token_file"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

# `--unsafe` because the crash is raised through `run_script`, which is gated.
"$BIN" serve --mode http \
  --bind "127.0.0.1:${PORT}" \
  --allow-origin "http://localhost" \
  --token-file "$token_file" \
  --max-workers 2 \
  --unsafe \
  >"$server_log" 2>&1 &
server_pid=$!

headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: http://localhost"
  -H "Authorization: Bearer $token"
)
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"crash-signal-test","version":"0.1"},"capabilities":{}}}'
response_headers="$tmpdir/headers"

session_id=""
for _ in {1..100}; do
  if curl -sS -D "$response_headers" -o /dev/null "${headers[@]}" -d "$init" "$url" 2>/dev/null; then
    session_id="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$response_headers" | tr -d '\r')"
    [[ -n "$session_id" ]] && break
  fi
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
if [[ -z "$session_id" ]]; then
  echo "failed to initialize the supervisor" >&2
  cat "$server_log" >&2
  exit 1
fi
headers+=(-H "Mcp-Session-Id: $session_id")

mcp_json() {
  local payload
  payload="$(cat)"
  if jq -e . >/dev/null 2>&1 <<<"$payload"; then
    printf '%s\n' "$payload"
  else
    awk '/^data: / {sub(/^data: /, ""); print; exit}' <<<"$payload"
  fi
}

call() {
  local id="$1" name="$2" arguments="$3"
  curl -sS --max-time 60 "${headers[@]}" \
    -d "$(jq -cn --argjson id "$id" --arg name "$name" --argjson arguments "$arguments" \
      '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:$name,arguments:$arguments}}')" \
    "$url" | mcp_json
}

open_database() {
  local id="$1" path="$2"
  local response database
  response="$(call "$id" idb_open "$(jq -cn --arg path "$path" '{input_path:$path}')")"
  database="$(jq -r '.result.content[0].text | fromjson | .session.session_id' <<<"$response")"
  if [[ -z "$database" || "$database" == "null" ]]; then
    echo "idb_open failed for $path: $response" >&2
    cat "$server_log" >&2
    exit 1
  fi
  printf '%s' "$database"
}

wait_for_log() {
  local needle="$1" timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  while ((SECONDS <= deadline)); do
    if grep -Fq "$needle" "$server_log"; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

crashed="$(open_database 10 "$crashed_binary")"
survivor="$(open_database 11 "$survivor_binary")"
echo "   opened two sessions on two workers"

# Raise SIGSEGV synchronously on the worker's IDA thread. Before the guard
# retired the process, this same worker went on serving the same database.
crash="$(call 20 run_script "$(jq -cn --arg database "$crashed" \
  --arg code 'import signal
signal.raise_signal(signal.SIGSEGV)' '{database:$database,code:$code,timeout_secs:10}')")"
jq -e '.result.isError == true' <<<"$crash" >/dev/null || {
  echo "a guarded SIGSEGV was not reported as a failure: $crash" >&2
  cat "$server_log" >&2
  exit 1
}
jq -e '.result.content[0].text | contains("worker retired after a fatal signal")' \
  <<<"$crash" >/dev/null || {
  echo "the crash did not report a retired worker: $crash" >&2
  cat "$server_log" >&2
  exit 1
}
echo "   the crashing call reported the retirement"

# Retired, not reused: no later request can be routed to that process.
wait_for_log "marked IDA child worker dead" 20 || {
  echo "the worker that caught a signal was not retired" >&2
  cat "$server_log" >&2
  exit 1
}
echo "   the supervisor retired that worker"

# The retired worker's database lock does not outlive it. Nothing in the child
# released it — it was killed — so this is the parent cleaning up after a
# worker it retired, and the next open of that database depends on it.
crashed_lock="${crashed_binary%$fixture_ext}.imcp"
lock_deadline=$((SECONDS + 20))
while [[ -e "$crashed_lock" ]] && ((SECONDS <= lock_deadline)); do
  sleep 0.1
done
if [[ -e "$crashed_lock" ]]; then
  echo "the retired worker's lock file was left behind: $crashed_lock" >&2
  cat "$server_log" >&2
  exit 1
fi
echo "   the retired worker's database lock was cleaned up"

# Containment: the crash belonged to one session.
survivor_status="$(call 21 analysis_status "$(jq -cn --arg database "$survivor" '{database:$database}')")"
jq -e '.result.isError != true' <<<"$survivor_status" >/dev/null || {
  echo "an unrelated session did not survive the crash: $survivor_status" >&2
  cat "$server_log" >&2
  exit 1
}
echo "   the unrelated session kept working"

# The crashed session is invalidated rather than quietly reattached.
stale="$(call 22 analysis_status "$(jq -cn --arg database "$crashed" '{database:$database}')")"
jq -e '.result.isError == true' <<<"$stale" >/dev/null || {
  echo "a session whose worker caught a signal kept answering: $stale" >&2
  cat "$server_log" >&2
  exit 1
}
echo "   the crashed session is gone"

# And the supervisor is still able to open a fresh one.
fresh="$(open_database 30 "$fresh_binary")"
[[ "$fresh" != "$crashed" ]] || {
  echo "the fresh session reused the crashed session ID" >&2
  exit 1
}
echo "   a fresh session opened on a new worker"

for close in "$survivor" "$fresh"; do
  call 40 idb_close "$(jq -cn --arg database "$close" '{database:$database}')" >/dev/null || true
done
echo "Supervisor guarded-signal retirement test passed"
