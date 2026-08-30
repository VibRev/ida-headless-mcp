#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8767}"
BIN="${MCP_BIN:-${MCP_HTTP_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
ORIGIN="${MCP_HTTP_ORIGIN:-http://localhost}"
IDB_PATH="${IDB_PATH:-fixtures/mini.i64}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

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
headers_file="$tmpdir/headers.log"
body_file="$tmpdir/body.log"
server_log="$tmpdir/server.log"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

"$BIN" serve --mode http --bind "127.0.0.1:$PORT" --token-file "$token_file" >"$server_log" 2>&1 &
server_pid=$!

init_payload='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"script-test","version":"0.1"},"capabilities":{}}}'

session_id=""
for _ in {1..100}; do
  if curl -sS -D "$headers_file" -o "$body_file" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    "${mcp_auth[@]}" \
    -H "Origin: $ORIGIN" \
    -d "$init_payload" \
    "http://127.0.0.1:$PORT/" >/dev/null 2>/dev/null; then
    session_id="$(awk -F': ' 'tolower($1)=="mcp-session-id" {print $2}' "$headers_file" | tr -d '\r')"
    if [[ -n "$session_id" ]]; then
      break
    fi
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ -z "$session_id" ]]; then
  echo "failed to obtain Mcp-Session-Id" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
fi

call_tool() {
  local request_id="$1"
  local tool_name="$2"
  local arguments_json="$3"
  curl -sS \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    "${mcp_auth[@]}" \
    -H "Origin: $ORIGIN" \
    -H "Mcp-Session-Id: $session_id" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${request_id},\"method\":\"tools/call\",\"params\":{\"name\":\"${tool_name}\",\"arguments\":${arguments_json}}}" \
    "http://127.0.0.1:$PORT/"
}

curl -sS \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  "${mcp_auth[@]}" \
  -H "Origin: $ORIGIN" \
  -H "Mcp-Session-Id: $session_id" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "http://127.0.0.1:$PORT/" >/dev/null

open_resp="$(call_tool 2 open_idb "{\"path\":\"$IDB_PATH\"}")"
echo "$open_resp" | grep -q "function_count" || {
  echo "open_idb failed" >&2
  echo "$open_resp" >&2
  [[ -s "$server_log" ]] && cat "$server_log" >&2
  exit 1
}

inline_resp="$(call_tool 3 run_script "{\"code\":\"import ida_funcs\\nprint(f'inline_simple_ok function_count={ida_funcs.get_func_qty()}')\"}")"
echo "$inline_resp" | grep -q "inline_simple_ok function_count=" || {
  echo "inline script output missing" >&2
  echo "$inline_resp" >&2
  exit 1
}

file_resp="$(call_tool 4 run_script "{\"file\":\"fixtures/test_analysis.py\"}")"
echo "$file_resp" | grep -q "total_functions=" || {
  echo "file-based script output missing" >&2
  echo "$file_resp" >&2
  exit 1
}

complex_resp="$(call_tool 5 run_script "{\"code\":\"import idautils\\nimport ida_funcs\\n\\ndef _func_info(ea):\\n    f = ida_funcs.get_func(ea)\\n    if not f:\\n        return None\\n    return (ida_funcs.get_func_name(ea), f.size(), ea)\\n\\ninfos = [_func_info(ea) for ea in idautils.Functions()]\\ninfos = [x for x in infos if x is not None]\\ninfos.sort(key=lambda t: t[1], reverse=True)\\nprint(f'complex_ok total={len(infos)} top={infos[:3]}')\"}")"
echo "$complex_resp" | grep -q "complex_ok total=" || {
  echo "complex inline script output missing" >&2
  echo "$complex_resp" >&2
  exit 1
}

syntax_resp="$(call_tool 6 run_script "{\"code\":\"def broken(:\\n    return 1\"}")"
echo "$syntax_resp" | grep -q '"isError":true' || {
  echo "syntax error response was not marked as MCP error" >&2
  echo "$syntax_resp" >&2
  exit 1
}
echo "$syntax_resp" | grep -q 'SyntaxError' || {
  echo "syntax error details missing" >&2
  echo "$syntax_resp" >&2
  exit 1
}
echo "$syntax_resp" | grep -q 'IDAPython script execution failed' || {
  echo "script failure summary missing" >&2
  echo "$syntax_resp" >&2
  exit 1
}

close_token="$(echo "$open_resp" | sed -n 's/.*\\\"close_token\\\"[[:space:]]*:[[:space:]]*\\\"\\([^\\\"]*\\)\\\".*/\\1/p')"
if [[ -n "$close_token" ]]; then
  close_args="{\"close_token\":\"$close_token\"}"
else
  close_args="{}"
fi

call_tool 7 close_idb "$close_args" >/dev/null

echo "HTTP script integration test passed"
