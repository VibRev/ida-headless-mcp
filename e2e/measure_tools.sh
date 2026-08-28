#!/usr/bin/env bash
# Measure the tools/list payload that Claude Code (and other MCP clients)
# load into context every session. Drives ida-headless-mcp via stdio, captures the
# tools/list response, and reports a per-tool ranking by JSON char count.
#
# Char count is deterministic and CI-friendly. For an exact token count,
# pipe the captured tools array through Anthropic count_tokens or your
# tokenizer of choice.
#
# Usage:
#   just measure-tools                # via the just recipe
#   MCP_BIN=./target/release/ida-headless-mcp ./e2e/measure_tools.sh
#                                     # legacy BIN= is still honoured
#   TOP=20 ./e2e/measure_tools.sh    # show top 20 tools (default 10)
#   FAIL_OVER_CHARS=50000 ./e2e/measure_tools.sh   # CI guard
set -euo pipefail

BIN="${MCP_BIN:-${BIN:-${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}}"
TOP="${TOP:-10}"
FAIL_OVER_CHARS="${FAIL_OVER_CHARS:-0}"  # 0 = no guard

[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

fifo="$(mktemp -u).fifo"
mkfifo "$fifo"
log="$(mktemp)"

cleanup() {
  exec 3>&- 2>/dev/null || true
  rm -f "$fifo" "$log"
  if [[ -n "${pid:-}" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$BIN" < "$fifo" > "$log" 2>&1 &
pid=$!
exec 3>"$fifo"

send() { echo "$1" >&3; }

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"measure","version":"0.1"},"capabilities":{}}}'
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

# Wait for initialize response
for _ in {1..30}; do
  grep -m1 '"id":1[,}]' "$log" 2>/dev/null | grep -q '"jsonrpc"' && break
  sleep 1
done

send '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

resp=""
for _ in {1..30}; do
  resp=$(grep -m1 '"id":2[,}]' "$log" 2>/dev/null | grep '"jsonrpc"' || true)
  [[ -n "$resp" ]] && break
  sleep 1
done

[[ -n "$resp" ]] || { echo "no tools/list response" >&2; cat "$log" >&2; exit 1; }

tools_json=$(echo "$resp" | jq '.result.tools')
total_chars=$(echo "$tools_json" | jq -c '.' | wc -c | tr -d ' ')
total_tools=$(echo "$tools_json" | jq 'length')
desc_chars=$(echo "$tools_json" | jq -r '[.[] | .description // ""] | join("")' | wc -c | tr -d ' ')
schema_chars=$(echo "$tools_json" | jq -c '[.[] | .inputSchema]' | wc -c | tr -d ' ')

echo "── tools/list payload ──"
printf "  tools:                %d\n" "$total_tools"
printf "  total JSON:           %s chars\n" "$total_chars"
printf "  └ descriptions:       %s chars\n" "$desc_chars"
printf "  └ schemas (combined): %s chars\n" "$schema_chars"
printf "  ~tokens (chars/4):    %d\n" "$((total_chars / 4))"
echo

echo "── top $TOP tools by chars ──"
echo "$tools_json" | jq -r '
  . as $t
  | range(0; length) as $i
  | "\($t[$i] | tojson | length)\t\($t[$i].name)"
' | sort -rn | head -n "$TOP" | awk '{printf "  %5d  %s\n", $1, $2}'

if (( FAIL_OVER_CHARS > 0 )) && (( total_chars > FAIL_OVER_CHARS )); then
  echo
  echo "FAIL: total $total_chars chars exceeds threshold $FAIL_OVER_CHARS" >&2
  exit 1
fi
