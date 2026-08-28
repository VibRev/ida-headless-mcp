#!/usr/bin/env bash
# Sequential supervisor stdio session test.
#
# The default entry point is the supervisor. Feed it one JSON-RPC request at a
# time over a FIFO and wait for that id before sending the next, so tools/call
# cannot race ahead of idb_open. Opens the checked-in/bootstrapped
# fixtures/mini.i64 (already analysed) rather than a freshly compiled raw
# binary, and uses function names plus resolve_function instead of hardcoded
# Mach-O addresses.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${MCP_BIN:-${MCP_STDIO_BIN:-${SERVER_BIN:-../target/release/ida-headless-mcp}}}"
IDB_PATH="${IDB_PATH:-$SCRIPT_DIR/fixtures/mini.i64}"
SESSION_ID="${SESSION_ID:-mini}"
OPEN_TIMEOUT="${OPEN_TIMEOUT:-120}"

if [[ ! -x "$BIN" ]]; then
  echo "missing server binary: $BIN" >&2
  exit 1
fi
if [[ ! -f "$IDB_PATH" ]]; then
  echo "missing IDB fixture: $IDB_PATH" >&2
  echo "Run 'just test-bootstrap' first." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

IDB_PATH="$(cd "$(dirname "$IDB_PATH")" && pwd)/$(basename "$IDB_PATH")"
RAW_BIN="${IDB_PATH%.i64}"
[[ "$RAW_BIN" == "$IDB_PATH" ]] && RAW_BIN=""

tmpdir="$(mktemp -d)"
fifo_in="$tmpdir/in.fifo"
log="$tmpdir/server.out"
errlog="$tmpdir/server.err"
idfile="$tmpdir/next_id"
echo 1 >"$idfile"
server_pid=""
next_id=1
passed=0
skipped=0
expected=0
LAST_PAYLOAD=""
FUNC_NAME="interesting_function"
FUNC_ADDR=""
PROCESSOR=""
FILE_TYPE=""

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

dump_logs() {
  echo "── server stdout ──" >&2
  cat "$log" >&2 || true
  echo "── server stderr (tail) ──" >&2
  tail -n 80 "$errlog" >&2 || true
}

send() {
  echo "$1" >&3
}

wait_response() {
  local target_id="$1"
  local timeout="${2:-30}"
  local elapsed=0
  while [[ "$elapsed" -lt "$timeout" ]]; do
    local line
    # Anchor at the JSON-RPC envelope so a huge tools/list schema cannot
    # supply a nested "id":N false positive.
    line="$(grep -E "^\\{\"jsonrpc\":\"2.0\",\"id\":${target_id}[,}]" "$log" 2>/dev/null | head -1 || true)"
    if [[ -n "$line" ]] && echo "$line" | jq -e --arg id "$target_id" \
      '(.id | tostring) == $id and (has("result") or has("error"))' >/dev/null 2>&1; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "server exited while waiting for id=$target_id" >&2
      dump_logs
      return 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo "timeout waiting for id=$target_id (${timeout}s)" >&2
  dump_logs
  return 1
}

payload_of() {
  echo "$1" | jq -c '
    if has("error") and (.error | type == "object") then
      {rpc_error: .error}
    elif (.result.structuredContent != null) then
      .result.structuredContent
    else
      (.result.content[0].text // empty) as $t
      | if ($t | type) == "string" and (($t | startswith("{")) or ($t | startswith("["))) then
          try ($t | fromjson) catch {text: $t}
        else
          {text: $t}
        end
    end
  '
}

is_error_true() {
  echo "$1" | jq -e '.result.isError == true' >/dev/null 2>&1
}

has_rpc_error() {
  echo "$1" | jq -e 'has("error")' >/dev/null 2>&1
}

session_error() {
  local payload="$1"
  echo "$payload" | jq -e '
    (.error | type == "string")
    and (.success != true)
    and (has("rpc_error") | not)
  ' >/dev/null 2>&1
}

mutation_failed() {
  local payload="$1"
  echo "$payload" | jq -e '
    (.status == "error")
    or ((.code | type) == "number" and .code != 0)
  ' >/dev/null 2>&1
}

fail_dump() {
  local label="$1"
  local resp="$2"
  echo "❌ $label" >&2
  echo "$resp" | jq . >&2 2>/dev/null || echo "$resp" >&2
  local payload
  payload="$(payload_of "$resp" 2>/dev/null || true)"
  if [[ -n "$payload" ]]; then
    echo "payload: $payload" >&2
  fi
  exit 1
}

ok() {
  echo "   ok  $1"
  passed=$((passed + 1))
}

skip() {
  echo "   skip $1"
  skipped=$((skipped + 1))
}

expect_fail() {
  echo "   expected $1"
  expected=$((expected + 1))
}

is_arm() {
  echo "${PROCESSOR}" | grep -qiE 'arm|aarch64'
}

# File-backed so $(rpc_call) subshells still share a monotonic id.
alloc_id() {
  ALLOCATED_ID="$(cat "$idfile")"
  echo $((ALLOCATED_ID + 1)) >"$idfile"
  next_id="$ALLOCATED_ID"
}

# Send tools/call and wait. Sets LAST_RPC. Safe to call from a subshell
# because the id counter lives in $idfile.
rpc_call() {
  local timeout="$1"
  local name="$2"
  local args_json="$3"
  alloc_id
  local id="$ALLOCATED_ID"
  local req
  [[ "$id" =~ ^[0-9]+$ ]] || { echo "invalid request id: $id" >&2; return 1; }
  req="$(jq -cn --argjson id "$id" --arg name "$name" --argjson args "$args_json" \
    '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:$name,arguments:$args}}')" || {
    echo "failed to build tools/call $name id=$id args=$args_json" >&2
    return 1
  }
  send "$req"
  LAST_RPC="$(wait_response "$id" "$timeout")"
  echo "$LAST_RPC"
}

# Routed worker tool: inject database="mini".
with_db() {
  jq -c --arg db "$SESSION_ID" '. + {database: $db}' <<<"$1"
}

# Default: require a successful MCP result (no rpc error, isError != true,
# no session-tool {error} payload). Sets LAST_PAYLOAD.
assert_ok() {
  local label="$1"
  local resp="$2"
  local extra="${3:-}"
  if has_rpc_error "$resp"; then
    fail_dump "$label: JSON-RPC error" "$resp"
  fi
  if is_error_true "$resp"; then
    fail_dump "$label: unexpected isError=true" "$resp"
  fi
  local payload
  payload="$(payload_of "$resp")"
  if session_error "$payload"; then
    fail_dump "$label: session error payload" "$resp"
  fi
  if mutation_failed "$payload"; then
    fail_dump "$label: mutation reported error (code/status)" "$resp"
  fi
  if [[ -n "$extra" ]] && ! echo "$payload" | jq -e "$extra" >/dev/null 2>&1; then
    fail_dump "$label: assertion failed: $extra" "$resp"
  fi
  LAST_PAYLOAD="$payload"
  ok "$label"
}

# Named expected failure: isError, session {error}, or mutation code != 0.
assert_expected() {
  local label="$1"
  local resp="$2"
  local reason="$3"
  if has_rpc_error "$resp"; then
    fail_dump "$label: JSON-RPC error (not an expected tool failure)" "$resp"
  fi
  local payload
  payload="$(payload_of "$resp")"
  if is_error_true "$resp" || session_error "$payload" || mutation_failed "$payload"; then
    local err
    err="$(echo "$payload" | jq -r '.error // .text // .status // "isError"')"
    expect_fail "$label ($reason): $err"
    return 0
  fi
  fail_dump "$label: expected failure ($reason) but the call succeeded" "$resp"
}

# ---------------------------------------------------------------------------
# Start supervisor (default entry — not `worker`)
# ---------------------------------------------------------------------------
mkfifo "$fifo_in"
: >"$log"
: >"$errlog"
# Keep JSON-RPC stdout separate from tracing stderr so a flushed log line
# cannot tear a response and wedge wait_response.
RUST_LOG="${RUST_LOG:-ida_mcp=trace}" "$BIN" <"$fifo_in" >"$log" 2>"$errlog" &
server_pid=$!
exec 3>"$fifo_in"

echo "🧪 Sequential supervisor stdio session"
echo "   bin  $BIN"
echo "   idb  $IDB_PATH"
echo "   session_id=$SESSION_ID"

# initialize → wait id=1 → notifications/initialized
alloc_id
init_id="$ALLOCATED_ID"
send "$(jq -cn --argjson id "$init_id" \
  '{jsonrpc:"2.0",id:$id,method:"initialize",params:{
      protocolVersion:"2024-11-05",
      clientInfo:{name:"stdio-session",version:"0.1"},
      capabilities:{}
    }}')"
init_resp="$(wait_response "$init_id" 20)"
if has_rpc_error "$init_resp"; then
  fail_dump "initialize" "$init_resp"
fi
if ! echo "$init_resp" | jq -e '.result.capabilities or .result.serverInfo' >/dev/null; then
  fail_dump "initialize: missing capabilities/serverInfo" "$init_resp"
fi
ok "initialize"
send '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

# tools/list
alloc_id
list_id="$ALLOCATED_ID"
send "$(jq -cn --argjson id "$list_id" \
  '{jsonrpc:"2.0",id:$id,method:"tools/list",params:{}}')"
list_resp="$(wait_response "$list_id" 20)"
if has_rpc_error "$list_resp"; then
  fail_dump "tools/list" "$list_resp"
fi
if ! echo "$list_resp" | jq -e '
  [.result.tools[].name] | index("idb_open")
  and index("idb_close")
  and index("tool_catalog")
  and index("tool_help")
' >/dev/null; then
  fail_dump "tools/list: missing session/discovery tools" "$list_resp"
fi
tool_count="$(echo "$list_resp" | jq '.result.tools | length')"
ok "tools/list ($tool_count tools)"

# idb_open — already-analysed IDB; 120s covers worker spawn + warmup
open_args="$(jq -cn --arg path "$IDB_PATH" --arg sid "$SESSION_ID" \
  '{input_path:$path, preferred_session_id:$sid}')"
open_resp="$(rpc_call "$OPEN_TIMEOUT" idb_open "$open_args")"
assert_ok "idb_open" "$open_resp" '
  .success == true
  and (
    (.message | type == "string")
    and ((.message | test("Binary opened")) or (.message | test("already open")))
  )
'
open_payload="$LAST_PAYLOAD"
opened_sid="$(echo "$open_payload" | jq -r '.session.session_id // empty')"
if [[ "$opened_sid" != "$SESSION_ID" ]]; then
  echo "❌ idb_open returned session_id='$opened_sid', expected '$SESSION_ID'" >&2
  echo "$open_payload" | jq . >&2
  exit 1
fi
PROCESSOR="$(echo "$open_payload" | jq -r '.session.metadata.processor // empty')"
FILE_TYPE="$(echo "$open_payload" | jq -r '.session.metadata.file_type // empty')"

# Discovery tools (routed; need database)
assert_ok "tool_catalog" \
  "$(rpc_call 30 tool_catalog "$(with_db '{"query":"decompile"}')")" \
  '.tools != null or .matches != null or .query != null'
assert_ok "tool_help" \
  "$(rpc_call 30 tool_help "$(with_db '{"name":"disasm"}')")" \
  '.name == "disasm" or .schema != null or .description != null'

# load_debug_info: ELF fixtures have no sibling .dSYM. Pass the raw binary
# when it exists (DWARF); otherwise accept the no-dSYM error as expected.
if [[ -n "$RAW_BIN" && -f "$RAW_BIN" ]]; then
  dbg_resp="$(rpc_call 30 load_debug_info "$(with_db "$(jq -cn --arg p "$RAW_BIN" '{path:$p}')")")"
else
  dbg_resp="$(rpc_call 30 load_debug_info "$(with_db '{}')")"
fi
if has_rpc_error "$dbg_resp"; then
  fail_dump "load_debug_info: JSON-RPC error" "$dbg_resp"
fi
dbg_payload="$(payload_of "$dbg_resp")"
if is_error_true "$dbg_resp" || session_error "$dbg_payload"; then
  dbg_err="$(echo "$dbg_payload" | jq -r '.error // .text // empty')"
  if echo "$dbg_err" | grep -qiE 'dSYM|File not found|Invalid path|debug info'; then
    expect_fail "load_debug_info (no usable debug sidecar on this fixture): $dbg_err"
  else
    fail_dump "load_debug_info: unexpected error" "$dbg_resp"
  fi
else
  ok "load_debug_info"
fi

# idb_meta — source of truth for processor / file type
assert_ok "idb_meta" \
  "$(rpc_call 30 idb_meta "$(with_db '{}')")" \
  '.processor != null and .file_type != null'
meta_payload="$LAST_PAYLOAD"
PROCESSOR="$(echo "$meta_payload" | jq -r '.processor')"
FILE_TYPE="$(echo "$meta_payload" | jq -r '.file_type')"
echo "   meta processor=$PROCESSOR file_type=$FILE_TYPE"

assert_ok "segments" \
  "$(rpc_call 30 segments "$(with_db '{}')")" \
  '(type == "array") or (try (.segments | type == "array") catch false)'

assert_ok "list_functions" \
  "$(rpc_call 30 list_functions "$(with_db '{"limit":20}')")" \
  '(type == "array") or (try (.functions | type == "array") catch false) or (has("total"))'

# Resolve by name. A leftover rename from a saved IDB is accepted.
resolve_one() {
  local name="$1"
  local resp payload addr
  rpc_call 30 resolve_function "$(with_db "$(jq -cn --arg n "$name" '{name:$n}')")" >/dev/null
  resp="$LAST_RPC"
  if has_rpc_error "$resp" || is_error_true "$resp"; then
    return 1
  fi
  payload="$(payload_of "$resp")"
  if session_error "$payload"; then
    return 1
  fi
  addr="$(echo "$payload" | jq -r '.address // empty')"
  [[ -n "$addr" && "$addr" != "null" ]] || return 1
  FUNC_NAME="$name"
  FUNC_ADDR="$addr"
}

if resolve_one interesting_function; then
  ok "resolve_function interesting_function → $FUNC_ADDR"
elif resolve_one interesting_function_renamed; then
  ok "resolve_function interesting_function_renamed → $FUNC_ADDR (already renamed in IDB)"
else
  echo "❌ resolve_function could not find interesting_function or interesting_function_renamed" >&2
  dump_logs
  exit 1
fi

assert_ok "addr_info" \
  "$(rpc_call 30 addr_info "$(with_db "$(jq -cn --arg n "$FUNC_NAME" '{name:$n}')")")" \
  '.'

assert_ok "function_at" \
  "$(rpc_call 30 function_at "$(with_db "$(jq -cn --arg n "$FUNC_NAME" '{name:$n}')")")" \
  '.'

assert_ok "set_comments" \
  "$(rpc_call 30 set_comments "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, comment:"mcp test comment", repeatable:false}')")")" \
  '.'

if [[ "$FUNC_NAME" != "interesting_function_renamed" ]]; then
  assert_ok "rename" \
    "$(rpc_call 30 rename "$(with_db '{"current_name":"interesting_function","name":"interesting_function_renamed","flags":0}')")" \
    '.'
  FUNC_NAME="interesting_function_renamed"
  if resolve_one interesting_function_renamed; then
    ok "resolve_function after rename → $FUNC_ADDR"
  else
    echo "❌ resolve_function after rename failed" >&2
    exit 1
  fi
else
  skip "rename (symbol already interesting_function_renamed)"
fi

assert_ok "disasm_by_name" \
  "$(rpc_call 30 disasm_by_name "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, count:20}')")")" \
  '.'

assert_ok "disasm_function_at" \
  "$(rpc_call 30 disasm_function_at "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, count:60}')")")" \
  '.'

if is_arm; then
  insn_pat="bl"
  op_pat="sp"
else
  insn_pat="call"
  op_pat="rsp"
fi
assert_ok "find_insns ($insn_pat)" \
  "$(rpc_call 60 find_insns "$(with_db "$(jq -cn --arg p "$insn_pat" \
    '{patterns:[$p], limit:5}')")")" \
  '.'

assert_ok "find_insn_operands ($op_pat)" \
  "$(rpc_call 60 find_insn_operands "$(with_db "$(jq -cn --arg p "$op_pat" \
    '{patterns:[$p], limit:5}')")")" \
  '.'

# patch_asm / ARM NOP only make sense on ARM. x86 would either assemble a
# different nop or silently write the wrong encoding.
if is_arm; then
  asm_resp="$(rpc_call 30 patch_asm "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, offset:0, line:"nop"}')")")"
  if has_rpc_error "$asm_resp"; then
    fail_dump "patch_asm: JSON-RPC error" "$asm_resp"
  fi
  asm_payload="$(payload_of "$asm_resp")"
  if is_error_true "$asm_resp" || session_error "$asm_payload"; then
    asm_err="$(echo "$asm_payload" | jq -r '.error // .text // empty')"
    if echo "$asm_err" | grep -qiE 'assembler|assemble|not supported|no assembler'; then
      expect_fail "patch_asm (no assembler on this ARM fixture): $asm_err"
    else
      fail_dump "patch_asm: unexpected error" "$asm_resp"
    fi
  else
    ok "patch_asm"
  fi
  assert_ok "patch (ARM NOP)" \
    "$(rpc_call 30 patch "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
      '{name:$n, offset:0, bytes:"1f 20 03 d5"}')")")" \
    '.'
else
  skip "patch_asm (processor=$PROCESSOR; ARM-only assembler test)"
  skip "patch (processor=$PROCESSOR; ARM NOP 1f 20 03 d5)"
fi

assert_ok "get_bytes" \
  "$(rpc_call 30 get_bytes "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, offset:0, size:4}')")")" \
  '.'

assert_ok "strings" \
  "$(rpc_call 30 strings "$(with_db '{"limit":10}')")" \
  '.'

# mini.c prints "result=%d"; keep a fallback for older fixtures.
str_query="result="
str_resp="$(rpc_call 30 find_string "$(with_db "$(jq -cn --arg q "$str_query" \
  '{query:$q, limit:10}')")")"
if has_rpc_error "$str_resp" || is_error_true "$str_resp"; then
  fail_dump "find_string $str_query" "$str_resp"
fi
str_payload="$(payload_of "$str_resp")"
str_hits="$(echo "$str_payload" | jq '
  if type == "array" then length
  elif .strings then (.strings | length)
  elif .matches then (.matches | length)
  elif .results then (.results | length)
  else 0 end
')"
if [[ "$str_hits" == "0" ]]; then
  str_query="value="
  assert_ok "find_string $str_query" \
    "$(rpc_call 30 find_string "$(with_db "$(jq -cn --arg q "$str_query" \
      '{query:$q, limit:10}')")")" \
    '.'
else
  ok "find_string $str_query"
fi

assert_ok "xrefs_to_string" \
  "$(rpc_call 30 xrefs_to_string "$(with_db "$(jq -cn --arg q "$str_query" \
    '{query:$q, limit:5}')")")" \
  '.'

# Address-only tools: fill in the address resolve_function just returned.
if [[ -z "$FUNC_ADDR" ]]; then
  echo "❌ no resolved address for xrefs/stack_frame" >&2
  exit 1
fi
assert_ok "xrefs_to" \
  "$(rpc_call 30 xrefs_to "$(with_db "$(jq -cn --arg a "$FUNC_ADDR" \
    '{address:$a, limit:5}')")")" \
  '.'

assert_ok "xrefs_from" \
  "$(rpc_call 30 xrefs_from "$(with_db "$(jq -cn --arg a "$FUNC_ADDR" \
    '{address:$a, limit:5}')")")" \
  '.'

assert_ok "local_types" \
  "$(rpc_call 30 local_types "$(with_db '{"limit":10}')")" \
  '.'

assert_ok "declare_type" \
  "$(rpc_call 30 declare_type "$(with_db "$(jq -cn '{decl:"typedef int mcp_int_t;", replace:true}')")")" \
  '.'

assert_ok "apply_types (function)" \
  "$(rpc_call 30 apply_types "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
    '{name:$n, decl:("int " + $n + "(int a, int b);"), strict:true}')")")" \
  '.'

# infer_types: a failed guess is a real answer (status=failed), not isError.
infer_resp="$(rpc_call 30 infer_types "$(with_db "$(jq -cn --arg n "$FUNC_NAME" '{name:$n}')")")"
if has_rpc_error "$infer_resp"; then
  fail_dump "infer_types: JSON-RPC error" "$infer_resp"
fi
if is_error_true "$infer_resp"; then
  fail_dump "infer_types: unexpected isError=true" "$infer_resp"
fi
infer_payload="$(payload_of "$infer_resp")"
if session_error "$infer_payload"; then
  fail_dump "infer_types: session error" "$infer_resp"
fi
ok "infer_types"

assert_ok "stack_frame" \
  "$(rpc_call 30 stack_frame "$(with_db "$(jq -cn --arg a "$FUNC_ADDR" \
    '{address:$a}')")")" \
  '.address != null'
frame_payload="$LAST_PAYLOAD"

# Prefer an existing local slot; fall back to -16 (original payload).
stack_off="$(echo "$frame_payload" | jq -r '
  ([.members[]? | select((.part // "" | ascii_downcase) | test("local"))][0].offset //
   [.members[]?][0].offset // empty)
')"
if [[ -z "$stack_off" || "$stack_off" == "null" ]]; then
  stack_off="-16"
fi

decl_resp="$(rpc_call 30 declare_stack "$(with_db "$(jq -cn --arg n "$FUNC_NAME" --argjson off "$stack_off" \
  '{name:$n, offset:$off, var_name:"mcp_local", decl:"int mcp_local;"}')")")"
if has_rpc_error "$decl_resp"; then
  fail_dump "declare_stack: JSON-RPC error" "$decl_resp"
fi
decl_payload="$(payload_of "$decl_resp")"
if is_error_true "$decl_resp" || session_error "$decl_payload" || mutation_failed "$decl_payload"; then
  decl_err="$(echo "$decl_payload" | jq -r '.error // .text // .status // "failed"')"
  expect_fail "declare_stack (offset $stack_off not accepted on this frame): $decl_err"
  skip "apply_types (stack) — declare_stack did not create mcp_local"
  skip "delete_stack — declare_stack did not create mcp_local"
else
  ok "declare_stack (offset $stack_off)"
  assert_ok "apply_types (stack)" \
    "$(rpc_call 30 apply_types "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
      '{name:$n, stack_name:"mcp_local", decl:"int mcp_local;", strict:true}')")")" \
    '.'
  assert_ok "delete_stack" \
    "$(rpc_call 30 delete_stack "$(with_db "$(jq -cn --arg n "$FUNC_NAME" \
      '{name:$n, var_name:"mcp_local"}')")")" \
    '.'
fi

assert_ok "structs" \
  "$(rpc_call 30 structs "$(with_db '{"limit":10}')")" \
  '.'
structs_payload="$LAST_PAYLOAD"

struct_name="$(echo "$structs_payload" | jq -r '
  ([.structs[]? | select((.member_count // 0) > 0)][0].name)
  // (.structs[0].name)
  // empty
')"
if [[ -z "$struct_name" || "$struct_name" == "null" ]]; then
  case "$FILE_TYPE" in
    MACHO*|Mach*|macho*) struct_name="mach_header_64"; struct_member="magic" ;;
    ELF*|Elf*|elf*) struct_name="Elf64_Ehdr"; struct_member="e_ident" ;;
    *) struct_name="" ;;
  esac
else
  struct_member=""
fi

if [[ -n "$struct_name" ]]; then
  if [[ -n "${struct_member:-}" ]]; then
    xref_args="$(jq -cn --arg n "$struct_name" --arg m "$struct_member" \
      '{name:$n, member_name:$m, limit:10}')"
    xref_label="xrefs_to_field $struct_name.$struct_member"
  else
    xref_args="$(jq -cn --arg n "$struct_name" \
      '{name:$n, member_index:0, limit:10}')"
    xref_label="xrefs_to_field $struct_name[0]"
  fi
  xref_resp="$(rpc_call 30 xrefs_to_field "$(with_db "$xref_args")")"
  if has_rpc_error "$xref_resp"; then
    fail_dump "$xref_label: JSON-RPC error" "$xref_resp"
  fi
  xref_payload="$(payload_of "$xref_resp")"
  if is_error_true "$xref_resp" || session_error "$xref_payload"; then
    xref_err="$(echo "$xref_payload" | jq -r '.error // .text // empty')"
    if echo "$xref_err" | grep -qiE 'unknown struct|not a struct|no local type'; then
      expect_fail "$xref_label (struct not in this fixture): $xref_err"
    else
      fail_dump "$xref_label: unexpected error" "$xref_resp"
    fi
  else
    ok "$xref_label"
  fi
else
  skip "xrefs_to_field (no struct names in this fixture)"
fi

assert_ok "search_structs" \
  "$(rpc_call 30 search_structs "$(with_db '{"query":"struct", "limit":10}')")" \
  '.'

assert_ok "imports" \
  "$(rpc_call 30 imports "$(with_db '{"limit":10}')")" \
  '.'

assert_ok "exports" \
  "$(rpc_call 30 exports "$(with_db '{"limit":10}')")" \
  '.'

assert_ok "analysis_status" \
  "$(rpc_call 30 analysis_status "$(with_db '{}')")" \
  '.'

close_resp="$(rpc_call 30 idb_close "$(jq -cn --arg db "$SESSION_ID" \
  '{database:$db, save:false}')")"
assert_ok "idb_close" "$close_resp" '
  .success == true
  and (.message | type == "string")
  and (.message | test("Session closed"))
'

# EOF the server; a clean exit after stdin closes is expected.
exec 3>&- || true
wait_elapsed=0
while kill -0 "$server_pid" 2>/dev/null && [[ "$wait_elapsed" -lt 20 ]]; do
  sleep 1
  wait_elapsed=$((wait_elapsed + 1))
done
if kill -0 "$server_pid" 2>/dev/null; then
  echo "⚠️  supervisor still running after stdin EOF; sending TERM" >&2
  kill -TERM "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
else
  wait "$server_pid" 2>/dev/null || true
fi
server_pid=""

echo "✅ Stdio session test passed  (ok=$passed skip=$skipped expected=$expected)"
