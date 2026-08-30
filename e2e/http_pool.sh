#!/usr/bin/env bash
# Exercise the HTTP worker-pool path. Cases:
#   concurrency  - a long call in one database must not block another
#   exhaustion   - an open fails once every worker is leased
#   crash        - a child exit is contained and the database can be re-opened
#   disconnect   - a dropped SSE stream closes the transport, not the database
#   manager-disconnect - dropped standalone SSE closes pooled rmcp session without opening IDA
#   second-open-failure - a failed open keeps the existing session's lease/IDB
#
# Every case talks to the supervisor: `idb_open` returns a `database` ID and
# every routed tool carries it. Worker-local `open_idb`/`close_idb` are not
# routable here — the supervisor owns database lifecycle.
set -euo pipefail

CASE="${POOL_TEST_CASE:-${1:-concurrency}}"
PORT="${PORT:-8765}"
BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
CONNECT_HOST="${MCP_HTTP_CONNECT_HOST:-127.0.0.1}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
MAX_WORKERS="${MAX_WORKERS:-2}"
# One worker is what makes a second open fail at all: the supervisor opens a
# second database in its own session rather than refusing, so "the open that
# fails" is now the one with no worker left to lease.
if [[ "${CASE}" == "second-open-failure" ]]; then
  MAX_WORKERS="${MAX_WORKERS_OVERRIDE:-1}"
fi
OP_TIMEOUT="${WORKER_OP_TIMEOUT:-20}"
DISCONNECT_GRACE="${WORKER_DISCONNECT_GRACE:-1}"

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "$cmd is required" >&2
    exit 1
  fi
done

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"

# serve --mode http needs a bearer token. Seed a throwaway one instead of
# letting the server create or read the operator's real ~/.vibrev/token.
token_file="$tmpdir/token"
mcp_token="vbr_test_$$"
printf '%s\n' "$mcp_token" >"$token_file"
chmod 600 "$token_file"
mcp_auth=(-H "Authorization: Bearer $mcp_token")
server_log="$tmpdir/server.log"
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"

cleanup() {
  if [[ -n "${slow_pid:-}" ]]; then
    kill "$slow_pid" >/dev/null 2>&1 || true
    wait "$slow_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${sse_a_pid:-}" ]]; then
    kill "$sse_a_pid" >/dev/null 2>&1 || true
    wait "$sse_a_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${sse_b_pid:-}" ]]; then
    kill "$sse_b_pid" >/dev/null 2>&1 || true
    wait "$sse_b_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

case "$IDB_PATH" in
*.i64) fixture_ext=".i64" ;;
*.idb) fixture_ext=".idb" ;;
*) fixture_ext="" ;;
esac

fixture_a="$tmpdir/mini-a${fixture_ext}"
fixture_b="$tmpdir/mini-b${fixture_ext}"
fixture_c="$tmpdir/mini-c${fixture_ext}"
if [[ "$CASE" != "manager-disconnect" ]]; then
  cp "$IDB_PATH" "$fixture_a"
  cp "$IDB_PATH" "$fixture_b"
  cp "$IDB_PATH" "$fixture_c"
fi

curl_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: $ORIGIN"
  "${mcp_auth[@]}"
)
# `/mcp`, not `/`: the Streamable HTTP endpoint has its own path, and posting
# to the root returns 404 before `initialize` is ever seen.
url="http://$CONNECT_HOST:$PORT/mcp"

# `--unsafe` because three of these cases drive the pool through `run_script`,
# which is gated behind it.
"$BIN" serve --mode http --token-file "$token_file" \
  --bind "$BIND_HOST:$PORT" \
  --max-workers "$MAX_WORKERS" \
  --worker-idle-timeout-secs 60 \
  --worker-op-timeout-secs "$OP_TIMEOUT" \
  --worker-disconnect-grace-secs "$DISCONNECT_GRACE" \
  --unsafe \
  >"$server_log" 2>&1 &
server_pid=$!

extract_json() {
  awk '/^\{/{print; exit} /^data: \{/{sub(/^data: /,""); print; exit}'
}

init_session() {
  local payload
  payload="$(jq -cn '{jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2024-11-05",clientInfo:{name:"pool-test",version:"0.1"},capabilities:{}}}')"
  for _ in {1..300}; do
    if curl -sS -D "$headers_file" -o "$body_file" \
      "${curl_headers[@]}" \
      -d "$payload" \
      "$url" >/dev/null 2>&1; then
      local sid
      sid="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers_file" | tr -d '\r')"
      if [[ -n "$sid" ]]; then
        curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
          -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
          "$url" >/dev/null
        printf '%s' "$sid"
        return 0
      fi
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  echo "failed to obtain Mcp-Session-Id" >&2
  cat "$server_log" >&2 || true
  exit 1
}

call_rpc() {
  local sid="$1" rid="$2" method="$3" params="$4" max_time="${5:-0}"
  local payload
  payload="$(jq -cn --argjson id "$rid" --arg method "$method" --argjson params "$params" \
    '{jsonrpc:"2.0",id:$id,method:$method,params:$params}')"
  local curl_args=(-sS)
  if [[ "$max_time" != "0" ]]; then
    curl_args+=(--max-time "$max_time")
  fi
  curl "${curl_args[@]}" "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    -d "$payload" \
    "$url" | extract_json
}

tool_call() {
  local sid="$1" rid="$2" tool="$3" args="$4" max_time="${5:-0}"
  local params
  params="$(jq -cn --arg name "$tool" --argjson arguments "$args" \
    '{name:$name,arguments:$arguments}')"
  call_rpc "$sid" "$rid" "tools/call" "$params" "$max_time"
}

tool_text() {
  jq -r '.result.content[0].text // empty'
}

assert_tool_ok() {
  local resp="$1" context="$2"
  local is_error
  is_error="$(printf '%s' "$resp" | jq -r '.result.isError // false')"
  if [[ "$is_error" == "true" || -z "$resp" ]]; then
    echo "$context failed" >&2
    printf '%s\n' "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
}

assert_tool_error_contains() {
  local resp="$1" needle="$2" context="$3"
  local is_error text
  is_error="$(printf '%s' "$resp" | jq -r '.result.isError // false')"
  text="$(printf '%s' "$resp" | tool_text)"
  if [[ "$is_error" != "true" || "$text" != *"$needle"* ]]; then
    echo "$context did not return expected error containing '$needle'" >&2
    printf '%s\n' "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
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

# Open a database and echo the session ID the supervisor minted for it. That
# ID, not the transport session, is what every routed tool is addressed to.
open_database() {
  local sid="$1" rid="$2" path="$3"
  local args resp database
  args="$(jq -cn --arg path "$path" '{input_path:$path}')"
  resp="$(tool_call "$sid" "$rid" idb_open "$args" 45)"
  assert_tool_ok "$resp" "idb_open $path"
  database="$(printf '%s' "$resp" | tool_text | jq -r '.session.session_id // empty')"
  if [[ -z "$database" ]]; then
    echo "idb_open returned no session ID for $path" >&2
    printf '%s\n' "$resp" | jq . >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
  printf '%s' "$database"
}

close_database() {
  local sid="$1" rid="$2" database="$3"
  tool_call "$sid" "$rid" idb_close "$(jq -cn --arg d "$database" '{database:$d}')" 10 >/dev/null || true
}

# Routed tools all take `database`; this saves spelling the merge each time.
database_args() {
  local database="$1" extra="${2:-{\}}"
  jq -cn --arg d "$database" --argjson extra "$extra" '{database:$d} + $extra'
}

start_standalone_stream() {
  local sid="$1" name="$2"
  curl -sS -N "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    "$url" >"$tmpdir/$name-sse.log" 2>&1 &
  local pid=$!
  sleep 0.5
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "standalone SSE stream for $name exited unexpectedly" >&2
    cat "$tmpdir/$name-sse.log" >&2 || true
    cat "$server_log" >&2 || true
    exit 1
  fi
  printf '%s' "$pid"
}

session_a="$(init_session)"
session_b="$(init_session)"
session_c="$(init_session)"

case "$CASE" in
concurrency)
  database_a="$(open_database "$session_a" 10 "$fixture_a")"
  database_b="$(open_database "$session_a" 20 "$fixture_b")"

  slow_args="$(database_args "$database_a" \
    "$(jq -cn --arg code 'import time; time.sleep(8); print("slow done")' \
      '{code:$code,timeout_secs:15}')")"
  slow_resp_file="$tmpdir/slow-response.json"
  tool_call "$session_a" 30 run_script "$slow_args" 20 >"$slow_resp_file" &
  slow_pid=$!
  sleep 1

  status_resp="$(tool_call "$session_b" 31 analysis_status "$(database_args "$database_b")" 4)"
  assert_tool_ok "$status_resp" "analysis_status while the other database is busy"
  if ! kill -0 "$slow_pid" 2>/dev/null; then
    echo "slow run_script finished before concurrency check completed" >&2
    cat "$slow_resp_file" >&2 || true
    exit 1
  fi

  wait "$slow_pid"
  unset slow_pid
  slow_resp="$(cat "$slow_resp_file")"
  assert_tool_ok "$slow_resp" "slow run_script"
  printf '%s' "$slow_resp" | tool_text | grep -q 'slow done' || {
    echo "slow run_script output missing marker" >&2
    printf '%s\n' "$slow_resp" | jq . >&2
    exit 1
  }
  close_database "$session_a" 90 "$database_a"
  close_database "$session_a" 91 "$database_b"
  echo "HTTP pool concurrency test passed"
  ;;

exhaustion)
  database_a="$(open_database "$session_a" 10 "$fixture_a")"
  database_b="$(open_database "$session_a" 20 "$fixture_b")"
  third_args="$(jq -cn --arg path "$fixture_c" '{input_path:$path}')"
  third_resp="$(tool_call "$session_c" 30 idb_open "$third_args" 15)"
  assert_tool_error_contains "$third_resp" "Worker pool exhausted" "third pooled open"
  close_database "$session_a" 90 "$database_a"
  close_database "$session_a" 91 "$database_b"
  echo "HTTP pool exhaustion test passed"
  ;;

second-open-failure)
  database_a="$(open_database "$session_a" 10 "$fixture_a")"
  second_args="$(jq -cn --arg path "$fixture_b" '{input_path:$path}')"
  second_resp="$(tool_call "$session_a" 20 idb_open "$second_args" 15)"
  assert_tool_error_contains "$second_resp" "Worker pool exhausted" "second pooled open"

  meta_resp="$(tool_call "$session_a" 30 idb_meta "$(database_args "$database_a")" 10)"
  assert_tool_ok "$meta_resp" "idb_meta after failed second open"
  printf '%s' "$meta_resp" | tool_text | jq -e '(.path // .input_file_path // "") | contains("mini-a")' >/dev/null || {
    echo "failed second open did not preserve the original database" >&2
    printf '%s\n' "$meta_resp" | jq . >&2
    cat "$server_log" >&2 || true
    exit 1
  }

  close_database "$session_a" 90 "$database_a"
  echo "HTTP pool second-open failure test passed"
  ;;

crash)
  database_a="$(open_database "$session_a" 10 "$fixture_a")"
  database_b="$(open_database "$session_a" 20 "$fixture_b")"
  crash_args="$(database_args "$database_a" \
    "$(jq -cn --arg code 'import os; os._exit(139)' '{code:$code,timeout_secs:10}')")"
  crash_resp="$(tool_call "$session_a" 30 run_script "$crash_args" 15)"
  assert_tool_error_contains "$crash_resp" "Worker" "crashing child call"

  status_resp="$(tool_call "$session_a" 31 analysis_status "$(database_args "$database_b")" 10)"
  assert_tool_ok "$status_resp" "analysis_status in unaffected session"

  database_c="$(open_database "$session_a" 40 "$fixture_c")"
  close_database "$session_a" 90 "$database_c"
  close_database "$session_a" 91 "$database_b"
  echo "HTTP pool crash-containment test passed"
  ;;

disconnect)
  # Databases used to belong to the transport session that opened them, and
  # dropping its stream released the worker. They do not any more: a database
  # is addressed by ID from any connection, so this asserts the boundary that
  # replaced it — the abandoned transport session is closed, and the database
  # it opened survives that and is still reachable from another connection.
  database_a="$(open_database "$session_a" 10 "$fixture_a")"

  sse_a_pid="$(start_standalone_stream "$session_a" session-a)"
  kill "$sse_a_pid" >/dev/null 2>&1 || true
  wait "$sse_a_pid" >/dev/null 2>&1 || true
  unset sse_a_pid

  if ! wait_for_log "closing pooled HTTP session after client stream disconnect" "$((DISCONNECT_GRACE + 5))"; then
    echo "pooled session manager did not close the abandoned transport session" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi

  status_resp="$(tool_call "$session_c" 30 analysis_status "$(database_args "$database_a")" 10)"
  assert_tool_ok "$status_resp" "database outliving the transport session that opened it"

  close_database "$session_c" 90 "$database_a"
  echo "HTTP pool disconnect cleanup test passed"
  ;;

manager-disconnect)
  # The same wiring with nothing open: the manager must close an abandoned
  # stream without a database having been opened over it.
  sse_a_pid="$(start_standalone_stream "$session_a" session-a)"
  kill "$sse_a_pid" >/dev/null 2>&1 || true
  wait "$sse_a_pid" >/dev/null 2>&1 || true
  unset sse_a_pid

  if ! wait_for_log "closing pooled HTTP session after client stream disconnect" "$((DISCONNECT_GRACE + 5))"; then
    echo "pooled session manager did not close abandoned standalone SSE stream" >&2
    cat "$server_log" >&2 || true
    exit 1
  fi
  echo "HTTP pool manager disconnect wiring test passed"
  ;;

*)
  echo "unknown POOL_TEST_CASE: $CASE" >&2
  exit 2
  ;;
esac
