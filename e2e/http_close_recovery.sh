#!/usr/bin/env bash
# Verify HTTP close-ownership recovery (issue #19, PRs #18 / #21):
# - owning HTTP session can call close_idb without a token
# - a different HTTP session is denied with a structured response
# - close_idb(force=true) recovers from a lost owner session
# - --session-keep-alive-secs is accepted on the CLI
set -euo pipefail

PORT="${PORT:-8765}"
BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
ALLOW_ORIGIN="${MCP_HTTP_ALLOW_ORIGIN:-http://localhost,http://127.0.0.1}"
BIND_HOST="${MCP_HTTP_BIND_HOST:-127.0.0.1}"
CONNECT_HOST="${MCP_HTTP_CONNECT_HOST:-127.0.0.1}"
IDB_PATH="${IDB_PATH:-fixtures/mini}"
SESSION_KEEP_ALIVE="${SESSION_KEEP_ALIVE:-1800}"

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

# CLI smoke: --session-keep-alive-secs must be present in serve --help
"$BIN" serve --help 2>&1 | grep -q -- '--session-keep-alive-secs' || {
  echo "serve --help missing --session-keep-alive-secs" >&2
  exit 1
}

tmpdir="$(mktemp -d)"

# serve --mode http needs a bearer token. Seed a throwaway one instead of
# letting the server create or read the operator's real ~/.vibrev/token.
token_file="$tmpdir/token"
mcp_token="vbr_test_$$"
printf '%s\n' "$mcp_token" >"$token_file"
chmod 600 "$token_file"
mcp_auth=(-H "Authorization: Bearer $mcp_token")
server_log="$tmpdir/server.log"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

curl_headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: $ORIGIN"
  "${mcp_auth[@]}"
)

url="http://$CONNECT_HOST:$PORT/"

"$BIN" serve --mode http --token-file "$token_file" \
  --bind "$BIND_HOST:$PORT" \
  --allow-origin "$ALLOW_ORIGIN" \
  --session-keep-alive-secs "$SESSION_KEEP_ALIVE" \
  >"$server_log" 2>&1 &
server_pid=$!

# init_session prints the Mcp-Session-Id of a fresh client to stdout.
init_session() {
  local headers="$tmpdir/init.h.$$"
  local body="$tmpdir/init.b.$$"
  local payload
  payload=$(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"recovery","version":"0.1"},"capabilities":{}}}')
  for _ in {1..300}; do  # 30s upper bound — generous for Rosetta-emulated Windows VM
    if curl -sS -D "$headers" -o "$body" \
      "${curl_headers[@]}" \
      -d "$payload" \
      "$url" >/dev/null 2>&1; then
      local sid
      sid="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers" | tr -d '\r')"
      if [[ -n "$sid" ]]; then
        # complete the handshake
        curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
          -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
          "$url" >/dev/null
        rm -f "$headers" "$body"
        printf '%s' "$sid"
        return 0
      fi
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  rm -f "$headers" "$body"
  echo "failed to obtain Mcp-Session-Id" >&2
  if [[ -s "$server_log" ]]; then
    echo "server log:" >&2
    cat "$server_log" >&2
  fi
  exit 1
}

# call <session-id> <id> <method> <params-json> -> raw response body
call() {
  local sid="$1" rid="$2" method="$3" params="$4"
  curl -sS "${curl_headers[@]}" -H "Mcp-Session-Id: $sid" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${rid},\"method\":\"${method}\",\"params\":${params}}" \
    "$url"
}

# tool_text <session-id> <id> <tool> <args-json> -> the tool's text payload
tool_text() {
  local sid="$1" rid="$2" tool="$3" args="$4"
  local raw
  raw=$(call "$sid" "$rid" "tools/call" \
    "{\"name\":\"${tool}\",\"arguments\":${args}}")
  # Accept both plain JSON (stateless) and SSE framing. Pull the first
  # JSON object from either layout.
  printf '%s\n' "$raw" \
    | awk '/^\{/{print; exit} /^data: \{/{sub(/^data: /,""); print; exit}' \
    | jq -r '.result.content[0].text // empty'
}

session_a="$(init_session)"
echo "   session A: $session_a"

# --- Phase 1: open_idb in session A, capture ownership metadata ---
open_a=$(tool_text "$session_a" 10 open_idb \
  "{\"path\":\"$IDB_PATH\"}")
echo "$open_a" | jq -e '.function_count' >/dev/null || {
  echo "open_idb (A) missing function_count" >&2
  echo "$open_a" >&2
  exit 1
}
close_token=$(echo "$open_a" | jq -r '.close_token')
owner_id=$(echo "$open_a" | jq -r '.close_owner_session_id')
[[ -n "$close_token" && "$close_token" != "null" ]] || { echo "close_token missing in open_idb response" >&2; exit 1; }
[[ -n "$owner_id" && "$owner_id" != "null" ]] || { echo "close_owner_session_id missing" >&2; exit 1; }
echo "   open_idb returned close_token + close_owner_session_id"

# --- Phase 2: owning session closes WITHOUT the token (new shortcut) ---
close_a_notoken=$(tool_text "$session_a" 11 close_idb "{}")
echo "$close_a_notoken" | grep -qi "Database closed" || {
  echo "owning session should close without token; got: $close_a_notoken" >&2
  exit 1
}
echo "   owning session closed without token"

# --- Phase 3: re-open in A, then start a fresh HTTP session B ---
open_a2=$(tool_text "$session_a" 12 open_idb \
  "{\"path\":\"$IDB_PATH\"}")
owner_a2=$(echo "$open_a2" | jq -r '.close_owner_session_id')
[[ "$owner_a2" == "$owner_id" ]] || {
  echo "owner_session_id should be stable across reopens in same HTTP session" >&2
  echo "  expected=$owner_id got=$owner_a2" >&2
  exit 1
}
echo "   re-opened in A; owner_session_id stable"

session_b="$(init_session)"
echo "   session B: $session_b"
[[ "$session_b" != "$session_a" ]] || { echo "session B Mcp-Session-Id collided with A" >&2; exit 1; }

# --- Phase 4: session B without token/force gets structured denial ---
deny_b=$(tool_text "$session_b" 20 close_idb "{}")
echo "$deny_b" | jq -e '.closed == false' >/dev/null || {
  echo "session B close should be denied with closed:false; got: $deny_b" >&2
  exit 1
}
deny_owner=$(echo "$deny_b" | jq -r '.owner_session_id')
[[ "$deny_owner" == "$owner_id" ]] || {
  echo "denial owner_session_id should match A's; expected=$owner_id got=$deny_owner" >&2
  exit 1
}
echo "$deny_b" | jq -e '.hint | contains("force=true")' >/dev/null || {
  echo "denial hint should mention force=true; got: $deny_b" >&2
  exit 1
}
echo "   session B denied with structured payload"

# --- Phase 5: session B force=true overrides and closes ---
force_b=$(tool_text "$session_b" 21 close_idb '{"force":true}')
echo "$force_b" | grep -qi "Database closed" || {
  echo "force=true close should succeed; got: $force_b" >&2
  exit 1
}
echo "   force=true override closed the IDB"

# --- Phase 6: ownership cleared — a third session can claim ---
session_c="$(init_session)"
open_c=$(tool_text "$session_c" 30 open_idb \
  "{\"path\":\"$IDB_PATH\"}")
new_owner=$(echo "$open_c" | jq -r '.close_owner_session_id')
[[ -n "$new_owner" && "$new_owner" != "null" && "$new_owner" != "$owner_id" ]] || {
  echo "after force-close, a new session should be able to claim a new ownership; got owner=$new_owner" >&2
  exit 1
}
echo "   new session C claimed ownership after recovery"

# Best-effort cleanup
tool_text "$session_c" 31 close_idb '{"force":true}' >/dev/null || true

echo "HTTP close-recovery test passed"
