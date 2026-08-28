#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-8766}"
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
second_binary="$tmpdir/mini-second"
legacy_sse_log="$tmpdir/legacy-sse.log"

# The bearer token is unconditional on serve-http. Seed a throwaway
# token file rather than letting the server touch the real ~/.vibrev/token —
# a test must not create or read the operator's long-lived credential.
token_file="$tmpdir/token"
token="vbr_supervisor_test_$$"
printf '%s\n' "$token" >"$token_file"
chmod 600 "$token_file"
auth=(-H "Authorization: Bearer $token")

cleanup() {
  if [[ -n "${legacy_sse_pid:-}" ]]; then
    kill "$legacy_sse_pid" >/dev/null 2>&1 || true
    wait "$legacy_sse_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

# --allow-host is passed explicitly because Host checking is off by default:
# the bearer token is what stops DNS rebinding, and leaving the Host check on
# mostly rejects reverse proxies and container DNS names. Naming a host here
# turns it back on, which is what the assertions below actually exercise.
server_args=(
  serve-http
  --bind "127.0.0.1:${PORT}"
  --allow-origin "http://localhost"
  --allow-host "localhost"
  --token-file "$token_file"
)
if [[ "${SUPERVISOR_UNSAFE:-${COMPAT_UNSAFE:-0}}" == "1" ]]; then
  server_args+=(--unsafe)
fi
"$BIN" "${server_args[@]}" >"$server_log" 2>&1 &
server_pid=$!

headers=(
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "Origin: http://localhost"
  "${auth[@]}"
)
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"supervisor-test","version":"0.1"},"capabilities":{}}}'
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

# The cached-output download endpoint is behind the same Host/Origin guards as
# /mcp and /sse. A 403 before the id is even looked up is the point: the guard
# runs as a router-wide layer, so an unreachable output id cannot be probed
# from a disallowed origin.
bad_origin_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Origin: http://untrusted.example" \
    "http://127.0.0.1:${PORT}/output/nonexistent.json"
)"
if [[ "$bad_origin_status" != "403" ]]; then
  echo "output endpoint accepted a disallowed Origin (HTTP $bad_origin_status)" >&2
  exit 1
fi

bad_host_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Host: untrusted.example" \
    "http://127.0.0.1:${PORT}/output/nonexistent.json"
)"
if [[ "$bad_host_status" != "403" ]]; then
  echo "output endpoint accepted a disallowed Host (HTTP $bad_host_status)" >&2
  exit 1
fi

# The bearer token is enforced by the same router-wide layer, so it covers
# /output/ exactly as it covers /mcp. Both paths are checked, with no
# credential and with a wrong one: an unauthenticated caller must not be able
# to tell a cached output that exists from one that does not, and 401 (not
# 403) is the answer, because a credential *would* change it.
for path in "/mcp" "/output/nonexistent.json"; do
  no_token_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "Origin: http://localhost" \
      "http://127.0.0.1:${PORT}${path}"
  )"
  if [[ "$no_token_status" != "401" ]]; then
    echo "${path} served a request with no bearer token (HTTP $no_token_status)" >&2
    exit 1
  fi

  wrong_token_status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -H "Origin: http://localhost" \
      -H "Authorization: Bearer vbr_wrong_token" \
      "http://127.0.0.1:${PORT}${path}"
  )"
  if [[ "$wrong_token_status" != "401" ]]; then
    echo "${path} served a request with a wrong bearer token (HTTP $wrong_token_status)" >&2
    exit 1
  fi
done

# The unauthorized body must not describe the real token in any way.
unauthorized_body="$(
  curl -sS -H "Origin: http://localhost" \
    -H "Authorization: Bearer vbr_wrong_token" \
    "http://127.0.0.1:${PORT}/output/nonexistent.json"
)"
if grep -qF "$token" <<<"$unauthorized_body"; then
  echo "the 401 body leaked the accepted token" >&2
  exit 1
fi

# And with the right token, /output/ reaches the handler: 404 for an id that
# was never cached is proof the request got past the gate rather than being
# turned away at it.
good_token_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Origin: http://localhost" \
    "${auth[@]}" \
    "http://127.0.0.1:${PORT}/output/nonexistent.json"
)"
if [[ "$good_token_status" != "404" ]]; then
  echo "output endpoint with a valid token returned HTTP $good_token_status, expected 404" >&2
  exit 1
fi

# An unrouted path is covered too: the layer wraps the router's fallback, so
# probing for other endpoints without a credential gets 401, not 404.
unrouted_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Origin: http://localhost" \
    "http://127.0.0.1:${PORT}/healthz"
)"
if [[ "$unrouted_status" != "401" ]]; then
  echo "an unrouted path answered an unauthenticated probe (HTTP $unrouted_status)" >&2
  exit 1
fi

curl -sS "${headers[@]}" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
  "$url" >/dev/null

curl -sS -N \
  -H "Accept: text/event-stream" \
  -H "Origin: http://localhost" \
  "${auth[@]}" \
  "http://127.0.0.1:${PORT}/sse" >"$legacy_sse_log" &
legacy_sse_pid=$!
legacy_endpoint=""
for _ in {1..50}; do
  legacy_endpoint="$(
    awk '/^event: endpoint\r?$/ {
      getline
      sub(/^data: /, "")
      sub(/\r$/, "")
      print
      exit
    }' "$legacy_sse_log"
  )"
  [[ -n "$legacy_endpoint" ]] && break
  kill -0 "$legacy_sse_pid" 2>/dev/null || break
  sleep 0.1
done
if [[ "$legacy_endpoint" != /sse\?session=* ]]; then
  echo "legacy SSE endpoint event was not received" >&2
  cat "$legacy_sse_log" >&2
  cat "$server_log" >&2
  exit 1
fi

legacy_init='{"jsonrpc":"2.0","id":101,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"legacy-supervisor-test","version":"0.1"},"capabilities":{}}}'
legacy_status="$(
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -H "Origin: http://localhost" \
    "${auth[@]}" \
    -d "$legacy_init" \
    "http://127.0.0.1:${PORT}${legacy_endpoint}"
)"
if [[ "$legacy_status" != "202" ]]; then
  echo "legacy SSE initialize POST returned HTTP $legacy_status" >&2
  cat "$server_log" >&2
  exit 1
fi

legacy_message=""
for _ in {1..50}; do
  legacy_message="$(
    awk '/^event: message\r?$/ {
      getline
      sub(/^data: /, "")
      sub(/\r$/, "")
      print
      exit
    }' "$legacy_sse_log"
  )"
  [[ -n "$legacy_message" ]] && break
  kill -0 "$legacy_sse_pid" 2>/dev/null || break
  sleep 0.1
done
jq -e '.id == 101 and .result.protocolVersion == "2024-11-05"' \
  <<<"$legacy_message" >/dev/null || {
  echo "legacy SSE initialize response was not delivered on the event stream" >&2
  cat "$legacy_sse_log" >&2
  cat "$server_log" >&2
  exit 1
}
kill "$legacy_sse_pid" >/dev/null 2>&1 || true
wait "$legacy_sse_pid" >/dev/null 2>&1 || true
legacy_sse_pid=""

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
  local id="$1"
  local name="$2"
  local arguments="$3"
  curl -sS "${headers[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${arguments}}}" \
    "$url" | mcp_json
}

read_resource() {
  local id="$1"
  local uri="$2"
  curl -sS "${headers[@]}" \
    -d "$(jq -cn --argjson id "$id" --arg uri "$uri" \
      '{jsonrpc:"2.0",id:$id,method:"resources/read",params:{uri:$uri}}')" \
    "$url" | mcp_json
}

tool_count="$(
  curl -sS "${headers[@]}" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    "$url" | mcp_json | jq '.result.tools | length'
)"
# Read the expected count from the snapshot the Rust suite already enforces
# (tool_surface_matches_the_checked_in_snapshot) rather than keeping a third
# copy of the number here. A hardcoded copy would drift silently: this script is
# its only reader and it is not part of `just check`, so nothing would catch it.
snapshot="../tests/snapshots/tool-surface.json"
[[ -f "$snapshot" ]] || {
  echo "missing tool-surface snapshot: $snapshot" >&2
  exit 1
}
if [[ "${SUPERVISOR_UNSAFE:-${COMPAT_UNSAFE:-0}}" == "1" ]]; then
  expected_tool_count="$(jq -e '.counts.supervisor_unsafe' "$snapshot")"
else
  expected_tool_count="$(jq -e '.counts.supervisor_safe' "$snapshot")"
fi
[[ "$tool_count" == "$expected_tool_count" ]] || {
  echo "expected $expected_tool_count supervisor tools, got $tool_count" >&2
  exit 1
}

resource_count="$(
  curl -sS "${headers[@]}" \
    -d '{"jsonrpc":"2.0","id":50,"method":"resources/list","params":{}}' \
    "$url" | mcp_json | jq '.result.resources | length'
)"
[[ "$resource_count" == "8" ]] || {
  echo "expected 8 supervisor resources, got $resource_count" >&2
  exit 1
}
template_count="$(
  curl -sS "${headers[@]}" \
    -d '{"jsonrpc":"2.0","id":51,"method":"resources/templates/list","params":{}}' \
    "$url" | mcp_json | jq '.result.resourceTemplates | length'
)"
[[ "$template_count" == "4" ]] || {
  echo "expected 4 supervisor resource templates, got $template_count" >&2
  exit 1
}
cursor_resource="$(read_resource 52 "ida://cursor")"
jq -e '.result.contents[0].text | fromjson | .addr == null' \
  <<<"$cursor_resource" >/dev/null || {
  echo "headless cursor resource did not return an empty state: $cursor_resource" >&2
  exit 1
}
selection_resource="$(read_resource 53 "ida://selection")"
jq -e '.result.contents[0].text | fromjson | .selection == null' \
  <<<"$selection_resource" >/dev/null || {
  echo "headless selection resource did not return an empty state: $selection_resource" >&2
  exit 1
}

if [[ "${SUPERVISOR_SKIP_IDA:-${COMPAT_SKIP_IDA:-0}}" == "1" ]]; then
  echo "Supervisor HTTP catalog smoke test passed (IDA open skipped)"
  exit 0
fi
cp "$IDB_PATH" "$second_binary"

open_one="$(call 3 idb_open "$(jq -cn --arg path "$IDB_PATH" '{input_path:$path}')")"
database_one="$(jq -r '.result.content[0].text | fromjson | .session.session_id' <<<"$open_one")"
[[ -n "$database_one" && "$database_one" != "null" ]] || {
  echo "first idb_open failed: $open_one" >&2
  exit 1
}

metadata_resource="$(read_resource 54 "ida://idb/metadata")"
jq -e '.result.contents[0].text | fromjson |
  (.module | type == "string" and length > 0) and
  (.base | type == "string")' \
  <<<"$metadata_resource" >/dev/null || {
  echo "single-session metadata resource failed: $metadata_resource" >&2
  exit 1
}

open_two="$(call 4 idb_open "$(jq -cn --arg path "$second_binary" '{input_path:$path}')")"
database_two="$(jq -r '.result.content[0].text | fromjson | .session.session_id' <<<"$open_two")"
[[ -n "$database_two" && "$database_two" != "null" && "$database_two" != "$database_one" ]] || {
  echo "second idb_open did not create an independent session: $open_two" >&2
  exit 1
}

# Cross-face check: take a name from the tools/* face and look it up on the
# resources/* face. The name must come from the tool rather than be hardcoded,
# because a hardcoded one cannot tell "this binary has no such export" from
# "the resource layer reads the wrong shape" — both answer "not found". That
# distinction is load-bearing here: `imports`/`exports` return an object with
# the list under a key (hence `list_key` below), not a bare array, so a
# resource layer that reads the root as an array fails silently on every
# lookup.
resource_roundtrip() {
  local id="$1" tool="$2" list_key="$3" scheme="$4" label="$5"
  local answer name resource
  answer="$(call "$id" "$tool" "$(jq -cn --arg d "$database_one" \
    '{database:$d, offset:0, limit:10000}')")"
  name="$(jq -r --arg key "$list_key" \
    '.result.content[0].text | fromjson | .[$key][0].name // empty' <<<"$answer")"
  if [[ -z "$name" ]]; then
    echo "$tool returned no named entry to round-trip through ida://$scheme/: $answer" >&2
    exit 1
  fi
  resource="$(read_resource "$((id + 1))" \
    "ida://$scheme/$name?database=$database_one")"
  jq -e --arg name "$name" \
    '.result.contents[0].text | fromjson | .error == null and .name == $name' \
    <<<"$resource" >/dev/null || {
    echo "ida://$scheme/ could not find '$name', a name the $tool tool just returned." >&2
    echo "  This is the shape mismatch between the tool face and the resource face." >&2
    echo "  $label resource: $resource" >&2
    exit 1
  }
}

resource_roundtrip 155 exports exports export "database-scoped export"
resource_roundtrip 157 imports imports import "database-scoped import"

# The other half of the contract: the tools that stayed bare arrays must still
# come through. `segments` and `entrypoints` never grew an object root, so a
# fix that only understood object roots would break these instead.
for probe in "159 idb/segments" "160 idb/entrypoints"; do
  read -r probe_id probe_path <<<"$probe"
  probe_resource="$(read_resource "$probe_id" "ida://$probe_path?database=$database_one")"
  jq -e '.result.contents[0].text | fromjson | type == "array" and length > 0' \
    <<<"$probe_resource" >/dev/null || {
    echo "ida://$probe_path returned no entries: $probe_resource" >&2
    exit 1
  }
done

ambiguous_resource="$(read_resource 56 "ida://idb/metadata")"
jq -e '.error.message | contains("ambiguous")' \
  <<<"$ambiguous_resource" >/dev/null || {
  echo "unscoped multi-session resource was not rejected as ambiguous: $ambiguous_resource" >&2
  exit 1
}

# Session-scoped smoke over the routed native tools. The old version of this
# file asserted the exact response shapes the compat adapter synthesized; those
# shapes went away with the adapter, so the checks below verify that the
# supervisor routes each call to the right worker and that the worker answers
# without an error. Tighten them into shape assertions when running against a
# licensed IDA.
expect_ok() {
  local label="$1"
  local response="$2"
  jq -e '.result.isError != true' <<<"$response" >/dev/null || {
    echo "$label failed: $response" >&2
    exit 1
  }
}

list="$(call 5 idb_list '{}')"
[[ "$(jq -r '.result.content[0].text | fromjson | .count' <<<"$list")" == "2" ]] || {
  echo "idb_list did not report two sessions: $list" >&2
  exit 1
}

for database in "$database_one" "$database_two"; do
  functions="$(call 6 list_funcs "$(jq -cn --arg database "$database" \
    '{database:$database,offset:0,limit:10}')")"
  jq -e '.result.content[0].text | fromjson | .functions | type == "array" and length > 0' \
    <<<"$functions" >/dev/null || {
      echo "list_funcs failed for $database: $functions" >&2
      exit 1
    }

  status="$(call 7 analysis_status "$(jq -cn --arg database "$database" '{database:$database}')")"
  jq -e '.result.content[0].text | fromjson | .auto_is_ok == true' \
    <<<"$status" >/dev/null || {
    echo "analysis_status failed for $database: $status" >&2
    exit 1
  }
done

looked_up="$(call 50 lookup_funcs "$(jq -cn --arg database "$database_one" \
  '{database:$database,queries:["main"]}')")"
jq -e '.result.content[0].text | fromjson | .results[0].result.name == "main"' \
  <<<"$looked_up" >/dev/null || {
  echo "lookup_funcs failed: $looked_up" >&2
  exit 1
}
main_addr="$(jq -r '.result.content[0].text | fromjson | .results[0].result.address' <<<"$looked_up")"

expect_ok "int_convert" "$(call 51 int_convert "$(jq -cn --arg database "$database_one" \
  '{database:$database,inputs:["0x41"]}')")"
expect_ok "find_bytes" "$(call 52 find_bytes "$(jq -cn --arg database "$database_one" \
  '{database:$database,patterns:"?? ??",limit:2}')")"
expect_ok "export_funcs" "$(call 53 export_funcs "$(jq -cn --arg database "$database_one" \
  '{database:$database,addrs:["main"],format:"json"}')")"
# `roots` is documented as an address, not a name, and value_to_addresses
# enforces that — so pass the address lookup_funcs just resolved, the same
# main_addr the four calls below already use.
expect_ok "callgraph" "$(call 55 callgraph "$(jq -cn --arg database "$database_one" \
  --arg addr "$main_addr" '{database:$database,roots:[$addr],max_depth:2}')")"
expect_ok "search" "$(call 57 search "$(jq -cn --arg database "$database_one" \
  '{database:$database,targets:["call"],kind:"text",limit:2}')")"
expect_ok "idb_meta" "$(call 58 idb_meta "$(jq -cn --arg database "$database_one" \
  '{database:$database}')")"
expect_ok "segments" "$(call 59 segments "$(jq -cn --arg database "$database_one" \
  '{database:$database}')")"

# Worker-local database lifecycle must not be routable: the supervisor owns it.
lifecycle="$(call 60 open_idb "$(jq -cn --arg database "$database_one" --arg path "$IDB_PATH" \
  '{database:$database,path:$path}')")"
jq -e '.result.isError == true and
  (.result.content[0].text | fromjson | .error | contains("lifecycle is owned by the supervisor"))' \
  <<<"$lifecycle" >/dev/null || {
  echo "worker-local open_idb was not rejected: $lifecycle" >&2
  exit 1
}

if [[ "${SUPERVISOR_UNSAFE:-${COMPAT_UNSAFE:-0}}" == "1" ]]; then
  scripted="$(call 40 run_script "$(jq -cn --arg database "$database_one" \
    '{database:$database,code:"print(\"hello from ida\")"}')")"
  expect_ok "run_script" "$scripted"
  jq -e '.result.content[0].text | contains("hello from ida")' \
    <<<"$scripted" >/dev/null || {
    echo "run_script did not capture stdout: $scripted" >&2
    exit 1
  }
else
  hidden="$(call 41 run_script "$(jq -cn --arg database "$database_one" \
    '{database:$database,code:"1"}')")"
  jq -e '.result.isError == true and
    (.result.content[0].text | fromjson | .error | contains("--unsafe"))' \
    <<<"$hidden" >/dev/null || {
    echo "run_script was reachable without --unsafe: $hidden" >&2
    exit 1
  }
fi

if [[ "${SUPERVISOR_TEST_TOOL_SMOKE:-${COMPAT_TEST_TOOL_SMOKE:-0}}" == "1" ]]; then
  expect_ok "decompile" "$(call 31 decompile "$(jq -cn --arg database "$database_one" \
    --arg addr "$main_addr" '{database:$database,address:$addr}')")"
  expect_ok "disasm" "$(call 32 disasm "$(jq -cn --arg database "$database_one" \
    --arg addr "$main_addr" '{database:$database,address:$addr,count:8}')")"
  expect_ok "xrefs_to" "$(call 33 xrefs_to "$(jq -cn --arg database "$database_one" \
    --arg addr "$main_addr" '{database:$database,address:$addr,limit:20}')")"
  expect_ok "callees" "$(call 34 callees "$(jq -cn --arg database "$database_one" \
    --arg addr "$main_addr" '{database:$database,address:$addr}')")"
  expect_ok "imports" "$(call 35 imports "$(jq -cn --arg database "$database_one" \
    '{database:$database,limit:20}')")"
  expect_ok "set_comments" "$(call 37 set_comments "$(jq -cn --arg database "$database_two" \
    '{database:$database,target_name:"main",comment:"supervisor smoke test"}')")"
  expect_ok "rename" "$(call 38 rename "$(jq -cn --arg database "$database_two" \
    '{database:$database,current_name:"main",name:"supervisor_smoke_main"}')")"
  expect_ok "rename restore" "$(call 39 rename "$(jq -cn --arg database "$database_two" \
    '{database:$database,current_name:"supervisor_smoke_main",name:"main"}')")"
fi

concurrent_one="$tmpdir/concurrent-one.json"
concurrent_two="$tmpdir/concurrent-two.json"
call 10 analysis_status "$(jq -cn --arg database "$database_one" '{database:$database}')" \
  >"$concurrent_one" &
concurrent_one_pid=$!
call 11 analysis_status "$(jq -cn --arg database "$database_two" '{database:$database}')" \
  >"$concurrent_two" &
concurrent_two_pid=$!
wait "$concurrent_one_pid"
wait "$concurrent_two_pid"
for response in "$concurrent_one" "$concurrent_two"; do
  jq -e '.result.content[0].text | fromjson | .auto_is_ok != null' "$response" >/dev/null || {
    echo "concurrent analysis_status failed: $(<"$response")" >&2
    exit 1
  }
done

if [[ "${SUPERVISOR_TEST_WORKER_RECOVERY:-${COMPAT_TEST_WORKER_RECOVERY:-0}}" == "1" ]]; then
  command -v pgrep >/dev/null 2>&1 || {
    echo "pgrep is required for worker recovery testing" >&2
    exit 1
  }
  mapfile -t worker_pids < <(pgrep -P "$server_pid")
  [[ "${#worker_pids[@]}" -eq 2 ]] || {
    echo "expected two IDA workers, got ${#worker_pids[@]}: ${worker_pids[*]-}" >&2
    exit 1
  }
  kill -KILL "${worker_pids[0]}"
  sleep 0.2

  health_one="$(call 20 analysis_status "$(jq -cn --arg database "$database_one" '{database:$database}')")"
  health_two="$(call 21 analysis_status "$(jq -cn --arg database "$database_two" '{database:$database}')")"
  error_one="$(jq -r '.result.isError // false' <<<"$health_one")"
  error_two="$(jq -r '.result.isError // false' <<<"$health_two")"
  if [[ "$error_one" == "true" && "$error_two" == "false" ]]; then
    dead_database="$database_one"
    dead_path="$IDB_PATH"
    live_database="$database_two"
    live_health="$health_two"
  elif [[ "$error_one" == "false" && "$error_two" == "true" ]]; then
    dead_database="$database_two"
    dead_path="$second_binary"
    live_database="$database_one"
    live_health="$health_one"
  else
    echo "worker crash did not isolate exactly one database" >&2
    echo "first: $health_one" >&2
    echo "second: $health_two" >&2
    exit 1
  fi
  jq -e '.result.content[0].text | fromjson | .auto_is_ok != null' \
    <<<"$live_health" >/dev/null || {
    echo "surviving worker became unhealthy: $live_health" >&2
    exit 1
  }

  list_after_crash="$(call 23 idb_list '{}')"
  [[ "$(jq -r '.result.content[0].text | fromjson | .count' <<<"$list_after_crash")" == "1" ]] || {
    echo "crashed worker session was not removed automatically: $list_after_crash" >&2
    exit 1
  }

  reopened="$(call 24 idb_open "$(jq -cn --arg path "$dead_path" '{input_path:$path}')")"
  recovered_database="$(jq -r '.result.content[0].text | fromjson | .session.session_id' <<<"$reopened")"
  reused="$(jq -r '.result.content[0].text | fromjson | .warmup.reused // false' <<<"$reopened")"
  [[ -n "$recovered_database" &&
    "$recovered_database" != "null" &&
    "$recovered_database" != "$dead_database" &&
    "$reused" == "false" ]] || {
    echo "failed database was not reopened in a fresh session: $reopened" >&2
    exit 1
  }
  recovered_health="$(call 25 analysis_status \
    "$(jq -cn --arg database "$recovered_database" '{database:$database}')")"
  jq -e '.result.content[0].text | fromjson | .auto_is_ok != null' \
    <<<"$recovered_health" >/dev/null || {
    echo "reopened database is unhealthy: $recovered_health" >&2
    exit 1
  }
  database_one="$live_database"
  database_two="$recovered_database"
fi

call 8 idb_close "$(jq -cn --arg database "$database_one" '{database:$database,save:false}')" >/dev/null
call 9 idb_close "$(jq -cn --arg database "$database_two" '{database:$database,save:false}')" >/dev/null

echo "Supervisor HTTP multi-session integration test passed"
