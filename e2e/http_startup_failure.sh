#!/usr/bin/env bash
# A server that cannot start must fail loudly, not silently: a failed bind has
# to exit nonzero rather than log the error and return Ok(()), and it must never
# leave a process alive holding an IDA license with no listener.
#
# Needs no IDA license, database, or fixture: the port squatter is a pooled
# parent (which never initializes IDA) and every start under test dies at bind.
set -euo pipefail

BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
PORT="${PORT:-9990}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
WATCHDOG_SECS="${WATCHDOG_SECS:-30}"

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"

# serve-http needs a bearer token. This script never sends a request,
# but the servers it starts still need one, and pointing them at a throwaway
# file keeps them from creating the operator's real ~/.vibrev/token.
token_file="$tmpdir/token"
printf 'vbr_test_%s\n' "$$" >"$token_file"
chmod 600 "$token_file"
squatter_pid=""

cleanup() {
  if [[ -n "${squatter_pid:-}" ]]; then
    kill "$squatter_pid" >/dev/null 2>&1 || true
    wait "$squatter_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

fail() {
  echo "❌ $1" >&2
  shift
  for extra in "$@"; do
    echo "$extra" >&2
  done
  exit 1
}

# run_bounded <log> <secs> <args...> -> echoes the exit status; 137 means the
# watchdog had to SIGKILL it (i.e. the process wedged). No GNU `timeout` on
# macOS, and this must stay bash 3.2 safe.
run_bounded() {
  local log="$1" secs="$2"
  shift 2
  "$@" >"$log" 2>&1 &
  local pid=$!
  (
    sleep "$secs"
    kill -9 "$pid" >/dev/null 2>&1 || true
  ) &
  local watchdog=$!
  local rc=0
  wait "$pid" || rc=$?
  kill "$watchdog" >/dev/null 2>&1 || true
  wait "$watchdog" 2>/dev/null || true
  echo "$rc"
}

# --- Squat the port. A pooled parent binds in milliseconds and takes no license.
"$BIN" serve-http --bind "$BIND_HOST:$PORT" --token-file "$token_file" --max-workers 2 --min-workers 0 \
  >"$tmpdir/squatter.log" 2>&1 &
squatter_pid=$!

for _ in $(seq 1 100); do
  if grep -Fq "listening on" "$tmpdir/squatter.log" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$squatter_pid" 2>/dev/null; then
    fail "port squatter exited before binding" "$(cat "$tmpdir/squatter.log")"
  fi
  sleep 0.1
done
grep -Fq "listening on" "$tmpdir/squatter.log" ||
  fail "port squatter never bound $BIND_HOST:$PORT" "$(cat "$tmpdir/squatter.log")"
echo "   port $PORT squatted"

# --- Phase 1: single-worker must exit nonzero and must not wedge.
single_log="$tmpdir/single-worker.log"
single_rc="$(run_bounded "$single_log" "$WATCHDOG_SECS" \
  "$BIN" serve-http --bind "$BIND_HOST:$PORT" --token-file "$token_file")"

[[ "$single_rc" != "137" ]] ||
  fail "single-worker start WEDGED on an occupied port (watchdog SIGKILL after ${WATCHDOG_SECS}s)" \
    "$(cat "$single_log")"
[[ "$single_rc" != "0" ]] ||
  fail "single-worker start reported success on an occupied port" "$(cat "$single_log")"
# "cannot bind <addr>: <source>" is vibrev-kit's TransportError::Bind wording,
# not this repo's: the listener belongs to the kit, so this assertion has to
# track the kit's message rather than a local phrasing.
grep -Fq "cannot bind" "$single_log" ||
  fail "single-worker log never mentions the bind failure" "$(cat "$single_log")"
# A start that cannot bind must not take an IDA licence in the first place.
# There is no wedge left to detect here: `serve-http` dispatches to the
# supervisor and never calls `run_ida_loop` — only `worker` does — so a parked
# main thread is structurally impossible, and the watchdog check above is what
# proves the process died on its own. This line is what keeps the licence half
# true.
! grep -Fq "Initializing IDA library" "$single_log" ||
  fail "a start that could not bind still initialized IDA, taking a licence for nothing" \
    "$(cat "$single_log")"
echo "   single-worker exited $single_rc without taking an IDA licence"

# --- Phase 2: pooled must exit nonzero and must not claim a clean stop.
pooled_log="$tmpdir/pooled.log"
pooled_rc="$(run_bounded "$pooled_log" "$WATCHDOG_SECS" \
  "$BIN" serve-http --bind "$BIND_HOST:$PORT" --token-file "$token_file" --max-workers 2 --min-workers 0)"

[[ "$pooled_rc" != "137" ]] ||
  fail "pooled start hung on an occupied port" "$(cat "$pooled_log")"
[[ "$pooled_rc" != "0" ]] ||
  fail "pooled start reported success on an occupied port" "$(cat "$pooled_log")"
grep -Fq "cannot bind" "$pooled_log" ||
  fail "pooled log never mentions the bind failure" "$(cat "$pooled_log")"
! grep -Fq "Pooled HTTP server stopped" "$pooled_log" ||
  fail "pooled start logged a clean stop it never achieved" "$(cat "$pooled_log")"
echo "   pooled exited $pooled_rc without claiming a clean stop"

echo "✅ HTTP startup failure test passed"
