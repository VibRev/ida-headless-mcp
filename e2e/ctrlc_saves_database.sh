#!/usr/bin/env bash
# Ctrl+C must save the open database before the process leaves.
#
# IDA only writes a `.i64` when the database is closed and packed. A process
# that dies on the signal instead leaves the working files — `.id0`, `.id1`,
# `.nam`, `.til` — sitting next to the binary, which is the analysis lost in a
# shape that still looks like something is there. That was the bug: IDA resets
# the SIGINT disposition during `init_library()`, so the handler tokio installed
# was gone by the time a worker had a database open, and a terminal Ctrl+C —
# which signals the whole foreground process group — killed every worker at exit
# 130 while the supervisor was still asking them to close.
#
# Three cases, one per half of the fix plus the escape hatch:
#   1. a process-group interrupt, i.e. what the terminal actually sends
#   2. a bare worker signalled on its own, with no supervisor to save it
#   3. a second interrupt while IDA is busy, which gives up on saving
set -euo pipefail

PORT="${PORT:-8768}"
BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
url="http://127.0.0.1:${PORT}/mcp"

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

# A throwaway token file: a test must not create or read the operator's
# long-lived ~/.vibrev/token.
token_file="$tmpdir/token"
token="vbr_ctrlc_test_$$"
printf '%s\n' "$token" >"$token_file"
chmod 600 "$token_file"

cleanup() {
  for pid in ${server_pid:-} ${worker_pid:-}; do
    kill -9 "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  done
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

# The analysis is only worth asserting on if this run produced it. Copies of the
# raw binary, so every case starts with no `.i64` and no working files.
fixture_for() {
  local copy="$tmpdir/$1"
  # Inside a command substitution, so `set -e` would not stop the caller.
  cp "$IDB_PATH" "$copy" || {
    echo "missing fixture binary: $IDB_PATH (run 'just fixture')" >&2
    exit 1
  }
  printf '%s' "$copy"
}

# What IDA leaves behind when it is killed instead of asked to close.
assert_packed() {
  local binary="$1" case_name="$2" leftover=()
  for ext in id0 id1 id2 nam til; do
    [[ -e "$binary.$ext" ]] && leftover+=("$binary.$ext")
  done
  if ((${#leftover[@]})); then
    echo "$case_name: the database was not packed; left behind: ${leftover[*]}" >&2
    exit 1
  fi
  [[ -s "$binary.i64" ]] || {
    echo "$case_name: no .i64 was written for $binary" >&2
    exit 1
  }
  [[ -e "$binary.imcp" ]] && {
    echo "$case_name: the MCP lock outlived the process: $binary.imcp" >&2
    exit 1
  }
  return 0
}

await_exit() {
  local pid="$1" timeout_secs="$2"
  local deadline=$((SECONDS + timeout_secs))
  while ((SECONDS <= deadline)); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

echo "-- case 1: a process-group interrupt, as a terminal sends it"

# `set -m` puts the server in its own process group, so `kill -INT -pgid` below
# reproduces what a terminal does to a foreground job. Without the fix the
# workers share that group and are signalled along with it.
set -m
"$BIN" serve --mode http \
  --bind "127.0.0.1:${PORT}" \
  --token-file "$token_file" \
  >"$server_log" 2>&1 &
server_pid=$!
set +m

headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: http://localhost"
  -H "Authorization: Bearer $token"
)
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"ctrlc-test","version":"0.1"},"capabilities":{}}}'
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
[[ -n "$session_id" ]] || {
  echo "failed to initialize the supervisor" >&2
  cat "$server_log" >&2
  exit 1
}
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

supervised_binary="$(fixture_for supervised)"
open="$(curl -sS --max-time 120 "${headers[@]}" \
  -d "$(jq -cn --arg path "$supervised_binary" \
    '{jsonrpc:"2.0",id:10,method:"tools/call",params:{name:"idb_open",arguments:{input_path:$path,auto_analyse:true}}}')" \
  "$url" | mcp_json)"
jq -e '.result.isError != true' <<<"$open" >/dev/null || {
  echo "idb_open failed: $open" >&2
  cat "$server_log" >&2
  exit 1
}

pool_worker="$(pgrep -P "$server_pid" || true)"
[[ -n "$pool_worker" ]] || {
  echo "no child worker found under the supervisor" >&2
  cat "$server_log" >&2
  exit 1
}

# The fix that makes the rest of this case possible: a worker signalled together
# with its parent races the parent's close_idb and gets SIGKILLed mid-save.
server_pgid="$(ps -o pgid= -p "$server_pid" | tr -d ' ')"
worker_pgid="$(ps -o pgid= -p "$pool_worker" | tr -d ' ')"
[[ "$worker_pgid" != "$server_pgid" ]] || {
  echo "the worker shares the supervisor's process group ($worker_pgid); a terminal Ctrl+C would signal it directly" >&2
  exit 1
}
echo "   the worker is in its own process group ($worker_pgid, supervisor $server_pgid)"

kill -INT -"$server_pgid"
await_exit "$server_pid" 30 || {
  echo "the supervisor did not exit within 30s of SIGINT" >&2
  cat "$server_log" >&2
  exit 1
}
await_exit "$pool_worker" 30 || {
  echo "the worker outlived the supervisor it was interrupted with" >&2
  cat "$server_log" >&2
  exit 1
}
unset server_pid
assert_packed "$supervised_binary" "process-group interrupt"
echo "   the supervised database was packed to .i64"

echo "-- case 2: a bare worker, signalled with nobody to close it for it"

# The other half of the fix, on its own: no supervisor is involved, so saving
# depends entirely on the worker having taken SIGINT back from IDA.
worker_in="$tmpdir/worker.in"
worker_log="$tmpdir/worker.log"
mkfifo "$worker_in"

start_worker() {
  "$BIN" worker <"$worker_in" >"$tmpdir/worker.out" 2>"$worker_log" &
  worker_pid=$!
  # Held open for the lifetime of the worker; closing it would be an EOF, which
  # is a different shutdown path than the one under test.
  exec 3>"$worker_in"
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"ctrlc-test","version":"0.1"},"capabilities":{}}}' >&3
  sleep 1
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&3
}

wait_for_open() {
  local binary="$1" deadline=$((SECONDS + 120))
  while ((SECONDS <= deadline)); do
    grep -Fq "Database opened" "$worker_log" && return 0
    kill -0 "$worker_pid" 2>/dev/null || break
    sleep 0.2
  done
  echo "the worker never opened $binary" >&2
  cat "$worker_log" >&2
  exit 1
}

bare_binary="$(fixture_for bare)"
start_worker
printf '%s\n' "$(jq -cn --arg path "$bare_binary" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$path,auto_analyse:true}}}')" >&3
wait_for_open "$bare_binary"

kill -INT "$worker_pid"
await_exit "$worker_pid" 30 || {
  echo "the bare worker did not exit within 30s of SIGINT" >&2
  cat "$worker_log" >&2
  exit 1
}
wait "$worker_pid" 2>/dev/null || worker_status=$?
exec 3>&-
unset worker_pid
assert_packed "$bare_binary" "bare worker interrupt"
# 130 is `128 + SIGINT`, and it is now chosen rather than suffered: the same
# number an uncaught SIGINT produced, from a process that saved first.
[[ "${worker_status:-0}" -eq 130 ]] || {
  echo "bare worker interrupt: expected exit 130, got ${worker_status:-0}" >&2
  exit 1
}
echo "   the bare worker packed its database and exited 130"

echo "-- case 3: a second interrupt while IDA is busy gives up on saving"

# IDA is single-threaded and blocking, so an interrupt that arrives mid-call
# cannot be acted on until the SDK returns. The first press is recorded and the
# second is the way out — without it, a Ctrl+C during a long auto_wait would
# look ignored for minutes.
busy_binary="$(fixture_for busy)"
unset worker_status
start_worker
printf '%s\n' "$(jq -cn --arg path "$busy_binary" \
  '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"open_idb",arguments:{path:$path,auto_analyse:true}}}')" >&3
wait_for_open "$busy_binary"

# Occupies the IDA thread for far longer than this test is willing to wait, so
# an exit inside a few seconds can only have come from the second signal.
printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_script","arguments":{"code":"import time\ntime.sleep(120)","timeout_secs":120}}}' >&3
sleep 3

kill -INT "$worker_pid"
sleep 1
# Survives the first one, which is the whole distinction: before the fix this
# process was already gone by now, killed by the disposition IDA restored.
kill -0 "$worker_pid" 2>/dev/null || {
  echo "the first interrupt killed the worker outright instead of being recorded" >&2
  cat "$worker_log" >&2
  exit 1
}
grep -Fq "press Ctrl+C again" "$worker_log" || {
  echo "the first interrupt said nothing, so the second press is unguessable" >&2
  cat "$worker_log" >&2
  exit 1
}
echo "   the first interrupt was recorded and announced, not obeyed"

kill -INT "$worker_pid"
await_exit "$worker_pid" 15 || {
  echo "a second interrupt did not force the busy worker out" >&2
  cat "$worker_log" >&2
  exit 1
}
exec 3>&-
unset worker_pid
echo "   the second interrupt forced the exit without waiting for IDA"

echo "Ctrl+C save-then-exit test passed"
