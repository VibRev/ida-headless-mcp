# Migrating from the `ida-pro-mcp` compatible surface

Until 2026-08 the default entry point re-implemented the public contract of
[`mrexodia/ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp): 66 tools
whose names, schemas and response shapes were pinned to an upstream dump and
translated call-by-call into this server's own tools.

That layer is gone. This project keeps the *ideas* it borrowed — explicit
multi-database sessions, a `database` argument on every analysis tool, an
`idb_open` / `idb_list` / `idb_close` lifecycle — but no longer claims
contract-level compatibility. The tools it advertises are now the tools it
implements, with the schemas generated from its own request types.

## What changed

- The public surface is the native `#[tool]` catalog: **90 tools** by default,
  91 with `--unsafe` (was 66 / 69).
- Every analysis tool still takes `database`, still returned by `idb_open`.
- Database lifecycle is still supervisor-owned. The worker-local `open_idb`,
  `open_dsc` and `close_idb` are not routable; use `idb_open` / `idb_close`.
- `--unsafe` now gates exactly one tool, `run_script`.
- Composite tools that existed only as adapter aggregations are gone. Their
  inputs are all still reachable individually; see the table below.
- Six of them came back as native tools rather than aggregations:
  `survey_binary`, `analyze_function`, `analyze_component`,
  `diff_before_after`, `trace_data_flow` and `func_profile`. They are *not*
  the old adapter functions restored — they call the worker directly, carry
  explicit scan ceilings, and publish an `outputSchema` written as a
  cross-engine baseline rather than as a copy of the upstream payload. Field
  names and nesting therefore differ from the compat versions; read the
  schema, not the old docs. `analyze_component` is not a Python drop-in: it
  has no `prototype`, does not decompile, and collects shared-global data
  xrefs from function/basic-block starts rather than every instruction.
  `diff_before_after` applies one typed edit (`rename_func` / `set_type` /
  `set_comment`) and returns the two decompiles; `trace_data_flow` is a
  bounded xref BFS, not a call graph; `func_profile` is the cheap
  `analyze_function` cousin (counts, optional lists, no decompile).
- Newly reachable, because they had no upstream counterpart: `find_paths`,
  `xref_matrix`, `callers`, `xrefs_from`, `xrefs_to_string`, `pseudocode_at`,
  `addr_info`, `analyze_funcs`, `lumina_lookup`, `lumina_apply`, `open_dsc`
  (worker-local), `dsc_add_dylib`, `dsc_add_region`, `local_types`,
  `struct_info`, `disasm_by_name`, `disasm_function_at`, `find_string`,
  `analyze_strings`, `entrypoints`, `segments`, `task_status`,
  `recent_operations`, `bookmark_add`, `comment_append`, `sdk_mutation`.

## Response shape changes

Six tools changed the *shape* of a successful answer. All six had the same
cause: the old shape could not be described by an `outputSchema`, or left no
place to put the analysis-completeness block described in the next section.

| Tool | Was | Is |
|------|-----|-----|
| `basic_blocks` | bare array for one address, `{results}` for several | always `{results, analysis_coverage}` |
| `callees` | bare array for one address, `{results}` for several | always `{results, analysis_coverage}` |
| `callers` | bare array for one address, `{results}` for several | always `{results, analysis_coverage}` |
| `read_struct` | bare array for one address, `{results}` for several | always `{results}` |
| `imports` | bare array | `{imports, analysis_coverage}` |
| `exports` | bare array | `{exports, analysis_coverage}` |

For the first four, only the single-address arm moved: the per-address entries
keep the keys the multi-address arm already used (`address` plus
`basic_blocks` / `callees` / `callers` / `struct`, or `error`). One address that
fails still comes back as an error result rather than a success carrying an
error entry, so error handling is unchanged.

Why break them at all: an array-or-object root cannot be described by one
schema, and it cannot be described by an `anyOf` root either — the supervisor
decides whether to advertise its `{"result": ...}` wrapper by testing for
`type: "object"` at the root, so an `anyOf` root would have made the advertised
schema wrong for exactly the calls that pass a single address. `analyze_function`
had already settled the precedent that a fixed `{results, ...}` shape is worth
one extra nesting level. `imports` and `exports` moved for a simpler reason: a
bare array has nowhere to carry `analysis_coverage`.

Reading a single address now costs one unwrap:

```diff
- blocks = call("basic_blocks", address="0x1000")
+ blocks = call("basic_blocks", address="0x1000")["results"][0]["basic_blocks"]
- names  = call("exports")
+ names  = call("exports")["exports"]
```

## `ordinal` and `name` are now mutually exclusive

`read_struct`, `struct_info` and `xrefs_to_field` accepted both and let
`ordinal` win silently. On a stock `/bin/cat`, `ordinal: 2` together with
`name: "Elf64_Sym"` answered with `Elf64_Rela` and `isError: false` — the
caller named the type it wanted and got a different one. Passing both is now
an `Invalid parameters` error.

```diff
- call("read_struct", address=a, ordinal=7, name="stat")   # ordinal quietly won
+ call("read_struct", address=a, name="stat")              # say one thing
```

An ordinal that names a typedef or an enum — `local_types` lists those next to
structures — used to come back as `unknown struct ordinal: 8`, which reads as
"your ordinal went stale". It now says the ordinal is a typedef.

### What `ordinal` actually is

It is IDA's local-type-library ordinal (`get_numbered_type`), not a position in
any listing this server returns, and it is **stable** for the life of a
database. Measured directly: a `/bin/cat` opened with `run_auto_analysis:
false` grew from 5 local types to 26 while analysis ran and a `/bin/bash` from
5 to 87; in both, every pre-existing ordinal still named the same type
afterwards, and `declare_type` — with and without `replace` — only ever
appended. So a `local_types` → `read_struct(ordinal=…)` handoff is sound.

What does move is *pagination*: `local_types` and `structs` page by position
within the filtered listing, so a page taken while analysis is appending types
can shift. `analysis_coverage` is the signal; re-list from offset 0, or filter
by name.

## `search` and `find_bytes`: `total` was `limit`, and paging never advanced

Both tools bounded the worker's scan at `offset + limit` hits and then reported
the length of that bounded scan as `total`. Two consequences, neither visible
to the caller:

- `total` came back *equal to `limit`* for any query with more hits than the
  page. On a stock `/bin/cat`, `search(targets=["lib"])` answered `total: 1`
  with `limit: 1`, `total: 5` with `limit: 5`, and `total: 127` with
  `limit: 2000`.
- `next_offset` was computed as `offset + limit < total`, which the same
  ceiling makes arithmetically impossible. It was `null` on every call ever
  made — the tools were, in effect, unpaginated.

Together they read as "exactly `limit` matches, and that is all of them".

The scan now runs one hit past the requested page, so:

| field | was | is |
|-------|-----|----|
| `total` | length of a scan capped at `offset + limit` | matches the scan found; equals the real total unless the ceiling was hit |
| `total_is_lower_bound` | — | **new**, `true` when the scan stopped at its 20000-hit ceiling |
| `next_offset` | always `null` | present when another page exists, omitted otherwise |

```diff
  r = call("search", targets=["lib"], limit=50)["results"][0]
- pages = math.ceil(r["total"] / 50)      # always 1
+ while True:
+     ...
+     if "next_offset" not in r:
+         if r["total_is_lower_bound"]:
+             ...                          # ceiling reached; narrow the query
+         break
```

`total_is_lower_bound: true` with no `next_offset` means the 20000-hit ceiling
was reached and this call cannot page any further; narrow the query.

## Every `next_offset` is now omitted, never null

`next_offset` is present exactly when another page exists. Eight tools already
worked that way because they serialize a struct that declares
`skip_serializing_if`. Four assembled their answer with a JSON literal instead
and emitted `"next_offset": null` on the last page: `analyze_strings`,
`list_globals`, `search` and `find_bytes`. All four now omit it, which is also
what their published schemas already claimed.

```diff
- if resp.get("next_offset") is not None:
+ if "next_offset" in resp:
```

Both spellings work for the eight that were already correct, and only the
second works everywhere now.

## The string tools no longer answer out of a stale index

`strings`, `find_string`, `analyze_strings` and `xrefs_to_string` read IDA's
string list, an index the loader builds *once* — before auto-analysis has
decided which byte runs are code. Nothing rebuilt it afterwards, so every
string answer for the rest of the session came from the loader's guess.

Measured on a stock `/bin/cat` opened with `run_auto_analysis: false`:

| when | `strings.total` | `analysis_coverage.state` |
|------|-----------------|---------------------------|
| right after `idb_open` | 226 | `partial` |
| after `analyze_funcs` settled | 226 | **`complete`** |
| after an explicit `build_strlist()` | **194** | `complete` |

The middle row is the dangerous one: a stale count sitting next to a
completeness marker that says it is settled. `analysis_coverage` cannot cover
it — analysis really had finished, the index just predated it.

A call that starts a scan at `offset: 0` now rebuilds the index first, the way
IDA's own Strings window does. `total` on a settled database therefore drops to
the settled number (194 rather than 226 on `/bin/cat`), and `survey_binary`'s
`total_strings` and `analyze_function`'s `referenced_strings` move with it,
because both scan from offset 0.

Continuation pages (`offset > 0`) deliberately do *not* rebuild: paging is by
position, so refreshing mid-sequence would renumber the offsets the caller was
just handed. One rebuild per pagination sequence, not one per page. Cost is a
single pass over the defined string items — 1-3 ms on `/bin/cat`, 32 ms on a
1.2 MB `/bin/bash` with 3816 strings.

`total` was never a function of `limit` in these tools, and still is not; if two
calls disagree, they were reading the index at two different moments.

## Failed mutations now set `isError`

Four tools ask IDA to change the database and get an `int` back rather than a
`Result`. They used to report the failure *inside* a successful envelope:

```json
{ "isError": false, "structuredContent": { "code": -5, "status": "error" } }
```

A client that reads `isError` — which is what MCP says to read — saw a
successful `declare_stack` and carried on with a stack frame that had not
changed. All four now answer `isError: true` when the operation did not happen:

| Tool | Failure marker in the payload |
|------|-------------------------------|
| `declare_stack` | `code != 0` |
| `delete_stack` | `code != 0` |
| `apply_types` | `applied: false` (address arm) or `code != 0` (stack arm) |
| `declare_type` | `code != 0`, or `errors != 0` for `multi: true` |

The payload is not lost. The failing call keeps the object the tool's
`outputSchema` describes as the error's `structuredContent`, and `content[0]`
is a sentence naming the tool, the function address and IDA's code:

```json
{
  "isError": true,
  "content": [{"type": "text", "text": "declare_stack did not define the stack variable: IDA returned code -5 for frame offset -8 of the function at 0x2000. …"}],
  "structuredContent": {"function": "0x2000", "name": "y", "offset": -8, "code": -5, "status": "error"}
}
```

```diff
  r = call("declare_stack", address="0x2000", offset=-8, decl="not a type ;;;")
- if r["structuredContent"]["code"] != 0:    # the only way to notice
+ if r["isError"]:                           # enough on its own
```

On the multi-session supervisor surface — which is what both stdio and HTTP
serve — the structured half collapses into the `{"error": "..."}` envelope
every routed worker failure already uses, so read `isError` first and
`content[0].text`, which still spells out the code, for the reason. Only a
direct client of the `worker` subcommand gets the object.

The failure messages are built from the tool name and numbers only, never from
a symbol name the database supplied: the supervisor classifies a child failure
by substring (`worker channel closed`, `timed out after`, `cancelled`), and a
variable called `cancelled` must not be able to masquerade as a cancelled call.

Not changed, because they are queries rather than mutations, and a negative
answer is a real answer: `infer_types` (`code: 0`, `status: "failed"` means
IDA had no guess) and `lumina_lookup` (`applied: false` means no match on the
server). `sdk_mutation` already failed loudly.

## `analysis_coverage`

`open_idb` returns as soon as the database is loadable, which is *before*
auto-analysis settles. Tools called in that window answer with numbers that
look final and are not: on a stock `/bin/cat`, `list_funcs` reports 66
functions in that window and 161 once analysis settles, and `survey_binary`
reports zero call edges where the settled answer is 253.

Every tool whose answer is a count, a list or a nullable slot read out of an
index the analyzer *writes* now carries a mandatory `analysis_coverage` object:

```json
{
  "complete": false,
  "state": "partial",
  "analysis_running": true,
  "engine_state": "AU_NONE",
  "note": "Auto-analysis was still running when this was read; every count and list here is a lower bound. Poll analysis_status until auto_is_ok, or call analyze_funcs, then read again."
}
```

- It is never omitted and never null — a completeness marker that disappears
  would disappear exactly when it matters.
- `complete` is the one-bool answer. `state` is `complete`, `partial` or
  `unknown` (the engine could not be asked; treat it as `partial`).
- Do not branch on `engine_state`. IDA's `AU_*` value is not a readiness
  signal: a fully analyzed `/bin/cat` still reports `AU_NONE`.
- Calls are never refused for being early. Partial data is still useful — a
  segment table does not need analysis — you just have to be able to see that
  it is partial.

Carrying it: `addr_info`, `analyze_component`, `analyze_strings`, `basic_blocks`,
`callees`, `callers`, `callgraph`, `export_funcs`, `exports`,
`find_insn_operands`, `find_insns`, `find_paths`, `find_string`, `func_profile`,
`idb_meta`, `imports`, `list_funcs`, `list_functions`, `list_globals`,
`local_types`, `search`, `search_structs`, `strings`, `structs`,
`survey_binary`, `trace_data_flow`, `xref_matrix`, `xrefs_from`, `xrefs_to`,
`xrefs_to_field`, `xrefs_to_string`.

Deliberately not carrying it: `segments`, `entrypoints`, `find_bytes`,
`get_bytes` and the other byte-level reads, all measured stable across the
transition because they read loader-owned or raw data; `function_at`,
`decompile` and `resolve_function`, which fail loudly rather than quietly when
analysis has not reached the target; and `read_struct`, which decodes bytes
through a layout the caller named.

## Tool name mapping

| Old (compat) | New (native) |
|--------------|--------------|
| `add_bookmark` | `bookmark_add` |
| `analyze_batch` | `analyze_function` with an array of addresses (different response shape) |
| `analyze_component` | `analyze_component` — reimplemented natively, different response shape (not a Python drop-in) |
| `analyze_function` | `analyze_function` — reimplemented natively, different response shape |
| `append_comments` | `comment_append` |
| `basic_blocks` | `basic_blocks` |
| `callees` | `callees` |
| `callgraph` | `callgraph` |
| `declare_stack` | `declare_stack` |
| `declare_type` | `declare_type` |
| `decompile` | `decompile` |
| `define_code` | sdk_mutation (action: define_code) |
| `define_func` | sdk_mutation (action: define_func) |
| `delete_stack` | `delete_stack` |
| `diff_before_after` | `diff_before_after` — reimplemented natively, different response shape (typed action, not `action_args`) |
| `disasm` | `disasm` |
| `entity_query` | list_funcs / list_globals / imports / exports / strings — each now takes `regex`, `sort_by` and `descending` |
| `enum_upsert` | sdk_mutation (action: enum_upsert_member) |
| `export_funcs` | `export_funcs` |
| `find` | search + xrefs_to |
| `find_bytes` | `find_bytes` |
| `find_regex` | `strings` with `regex`, or `find_string` with `regex: true` |
| `find_xref_signatures` | `xrefs_to`, then `make_signature` with the resulting address array |
| `force_recompile` | sdk_mutation (action: mark_cfunc_dirty) |
| `func_profile` | `func_profile` — reimplemented natively, different response shape (counts by default; no decompile / disasm / prototype) |
| `func_query` | `list_funcs` (now with `regex`, `min_size`, `max_size`, `sort_by`) |
| `get_bytes` | `get_bytes` |
| `get_global_value` | `get_global_value` |
| `get_int` | `get_int` (signed and byte-order aware; `get_u8`/`get_u16`/`get_u32`/`get_u64` also remain) |
| `get_string` | `get_string` |
| `idb_close` | idb_close (unchanged) |
| `idb_list` | idb_list (unchanged) |
| `idb_open` | idb_open (unchanged) |
| `idb_save` | sdk_mutation (action: save) |
| `imports` | `imports` |
| `imports_query` | `imports` (now with `filter`, `regex`, `module`) |
| `infer_types` | `infer_types` |
| `insn_query` | find_insns / find_insn_operands (now scoped by `function` / `segment` / `start`+`end`) |
| `int_convert` | `int_convert` |
| `list_funcs` | `list_funcs` |
| `list_globals` | `list_globals` |
| `lookup_funcs` | `lookup_funcs` |
| `make_data` | sdk_mutation (action: make_data) |
| `make_signature` | `make_signature` |
| `make_signature_for_function` | `make_signature` (a function address is just an address) |
| `make_signature_for_range` | `make_signature` with `end` |
| `patch` | `patch` |
| `patch_asm` | `patch_asm` |
| `put_int` | `put_int` |
| `py_eval` | run_script (code) |
| `py_exec_file` | run_script (file) |
| `read_struct` | `read_struct` |
| `rename` | `rename` |
| `search_structs` | search_structs / structs |
| `search_text` | `search` (now scoped, with `code_only`) |
| `server_health` | `server_health`（supervisor 会话工具；忙时不进 IDA 线程） |
| `set_comments` | `set_comments` |
| `set_op_type` | sdk_mutation (action: set_op_type) |
| `set_type` | `apply_types` |
| `stack_frame` | `stack_frame` |
| `survey_binary` | `survey_binary` — reimplemented natively, different response shape |
| `trace_data_flow` | `trace_data_flow` — reimplemented natively, different response shape (xref BFS, not a call graph) |
| `type_apply_batch` | `apply_types` |
| `type_inspect` | local_types / struct_info |
| `type_query` | local_types / structs (now with `kind`, `regex`, `sort_by`) |
| `undefine` | sdk_mutation (action: undefine) |
| `xref_query` | xrefs_to / xrefs_from (now with `kind`, `dedup`, `include_function`) |
| `xrefs_to` | `xrefs_to` |
| `xrefs_to_field` | `xrefs_to_field` |

## Resources

Unchanged: `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`,
`ida://cursor`, `ida://selection`, `ida://types`, `ida://structs`,
`ida://databases`, plus the `ida://struct/{name}`, `ida://import/{name}`,
`ida://export/{name}` and `ida://xrefs/from/{addr}` templates.

IDB-backed resources use the only open database automatically. If multiple
databases are open, append `?database=<session_id>`, for example
`ida://idb/metadata?database=<session_id>`.

`ida://cursor` and `ida://selection` stay present and return the empty state:
there is no GUI in a headless worker.

## Beyond the upstream surface

The mapping table above answers "where did tool X go". It does not say where
this server now does *more* than the tool it replaced. Everything in this
section has no upstream counterpart, or has one that takes fewer inputs.

### Scan scope

`find_insns`, `find_insn_operands` and `search` walked every segment of the
database unconditionally. Looking at one function meant scanning the whole
binary and filtering client-side. All three now take one of:

- `function` — the chunk range of the function containing an address
- `segment` — one segment by name
- `start` + `end` — an explicit half-open range

Naming two is an error rather than a precedence rule. The instruction scanners
also take `max_scan` (default 500000 instructions) and report `scanned` plus
`scan_truncated`, so a bounded answer cannot be read as a complete one.

Measured on the `mini` fixture: `find_insns(["mov"])` scans 410 instructions
database-wide and 8 with `function: "0x1000"`.

### Regular expressions

`filter` keeps its case-folded-substring meaning everywhere. A separate
`regex` field is the precise form, and naming both is an error:

| Tool | Regex field |
|------|-------------|
| `strings`, `analyze_strings`, `list_funcs`, `list_functions`, `list_globals`, `imports`, `exports`, `local_types`, `structs` | `regex` (a pattern string, replaces `filter`) |
| `find_string`, `xrefs_to_string` | `regex: true` (reinterprets `query`; mutually exclusive with `exact`) |
| `find_insns`, `find_insn_operands` | `regex: true` (reinterprets `patterns`, matched against the whole line) |

### Ordering and bounds

Listings take `sort_by` plus `descending`, and the numeric listings take
bounds. Sorting reads every match before paging — the tool descriptions say
so, because it turns a streaming walk into a full one.

| Tool | `sort_by` | Bounds |
|------|-----------|--------|
| `list_funcs` / `list_functions` | `address`, `name`, `size` | `min_size`, `max_size` |
| `strings`, `analyze_strings` | `address`, `length`, `content` | `min_length`, `max_length` |
| `list_globals`, `imports`, `exports` | `address`, `name` | — |
| `local_types`, `structs` | `ordinal`, `name` | — |

`descending` without `sort_by` is an error rather than a no-op.

### Narrowing by kind

- `imports` takes `module`, matching the external segment a symbol arrives
  through.
- `local_types` takes `kind`: `struct`, `union`, `enum`, `function`,
  `pointer`, `array`, `typedef`, `other`, or `udt` (struct or union).
  `structs` takes the same field to pick one half of its listing.
- `xrefs_to` / `xrefs_from` take `kind` (`any` / `code` / `data`), `dedup`
  (collapse repeated from/to/type triples) and `include_function` (attach the
  function each reference comes from). Filtering happens before paging, so
  `offset` counts the references you asked for.
- `search` takes `code_only`, keeping only matches in executable segments.

### `get_int` / `put_int`

`get_u8` / `get_u16` / `get_u32` / `get_u64` spell width in the tool name and
pin the other two axes: always unsigned, always the database's byte order.
Reading an `int32_t`, or a little-endian value out of a big-endian image, had
no answer.

`get_int` and `put_int` take one `ty` token carrying all three axes —
`i8`/`u8`/`i16`/`u16`/`i32`/`u32`/`i64`/`u64`, with an optional `le` or `be`
suffix. Values cross the wire as decimal strings, because a `u64` past 2^53
and a negative `i64` cannot both survive a JSON number. `put_int` range-checks
against the type: a value that does not fit is an error, not a truncation.

The four `get_u*` tools stay. They are shorter to call when you want exactly
what they do.

### `make_signature`

`sdk_mutation(action: signature_bytes)` returns the bytes at an address and a
mask string, leaving three jobs to the caller: pick a length, verify
uniqueness, and render the result. Verifying uniqueness is the one the caller
cannot do without a round trip per attempt.

`make_signature` grows a pattern one instruction at a time, wildcarding
operands, until it matches exactly one place in the database — then reports
`unique` from a real search rather than from the search that stopped growth.
It takes an address or an array of them, `format` (`ida` / `x64dbg` / `mask` /
`bitmask`), `wildcard_operands`, and `max_length`, and reports `truncated`
when the ceiling was hit without becoming unique. Passing `end` covers a fixed
range instead of searching.

Addresses outside an executable segment are refused: x86 decodes almost any
byte run into *something*, so a data address would otherwise produce a
confident-looking signature over a meaningless decode.

`sdk_mutation(action: signature_bytes)` remains for callers that want the raw
bytes and mask.

## Still deliberately absent

- The 22 `dbg_*` debugger tools
- IDA GUI discovery, selection, or control
- Launching or adopting GUI IDA processes
- Profiling every function in one call. `list_funcs(sort_by: "size",
  descending: true)` followed by `func_profile` with the resulting address
  array is the same answer without a full-database decode.

`idb_open` still accepts `prefer_headless`, `force_headless` and `prefer_gui`
(the last falls back to a headless worker); `force_gui` returns a stable
unsupported-mode error.

## Source of truth

`src/server/catalog.rs` reads the catalog back out of the generated `#[tool]`
router, and `tests/tool_surface.rs` pins the resulting names and counts against
`tests/snapshots/tool-surface.json`.
