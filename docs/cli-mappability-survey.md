# CLI mappability survey: 78 IDA tools vs the vibrev-kit schema→clap mapper

> **Snapshot, not a living document.** Measured against the 78-tool worker
> surface and committed on 2026-08-27; every count, table and percentage below
> is frozen at that reading. The worker surface has since grown to 85 tools
> (`tests/snapshots/tool-surface.json`), so treat the numbers as a record of
> what the mapper did on that day, not as current figures. Re-run the harness
> in the Repro section rather than patching entries in place.

Read-only census. Answers one question: if the schema→clap mapper derived a CLI
from `ida-headless-mcp`'s real MCP tool definitions, what would come out?

**Method.** Schemas are the real `tools/list` response from the worker, not the
docs. The classification was then *run*, not reasoned about: a throwaway harness
feeds that JSON straight into `vibrev_kit::cli` and reports the `clap::Command`
that actually comes back.

- Schemas: `target/release/ida-headless-mcp --unsafe worker` ← `initialize` +
  `notifications/initialized` + `tools/list` over stdio. 78 tools, 271 parameters.
  Saved at `target/tmp/survey/tools.json`.
- Harness: `vibrev/crates/vibrev-kit/examples/ida_schema_survey.rs`
  (`cargo run -p vibrev-kit --example ida_schema_survey -- tools.json`).
  Full transcript at `target/tmp/survey/harness_out.txt`.
- Mapper under test: `vibrev/crates/vibrev-kit/src/cli.rs` as of this survey.

Everything below is marked **[measured]** (harness output or raw schema JSON) or
**[read]** (inferred from reading `cli.rs` / IDA handler source).

Build note, unrelated to the survey but it costs an hour if you hit it: the shell
here exports `RUSTFLAGS=--remap-path-prefix=...`, and a set `RUSTFLAGS` **replaces**
`target.<triple>.rustflags` from `.cargo/config.toml`. That silently drops
`-C link-arg=-Wl,--allow-multiple-definition` and the link dies in a wall of
`rust-lld: error: duplicate symbol: idalib_*`. Prepend the repo flag to `RUSTFLAGS`
rather than editing the config.

---

## 1. Headline numbers [measured]

| | tools | params |
|---|---|---|
| **A — every parameter maps to a real flag** | **33 / 78** | 217 / 271 |
| **B — at least one param degrades to `--json-input`** | **0 / 78** | 0 / 271 |
| **C — at least one param hits a construct the mapper has no branch for** | **45 / 78** | 54 / 271 |

Class A parameter breakdown (271 total): 108 integer, 74 string, 34 boolean
(`--x` / `--no-x` pair), 1 array-of-string.

The harness confirms the shape of the tree end to end:

```
subcommands under `ida tool`: 78
tools that grew --json-input : 0
--flags                      : 271
  of which SetTrue (bool)    : 34
  of which Append (array)    : 3
  of which value-validated   : 0   <- PossibleValuesParser
  of which plain free-form   : 234
subcommands carrying the `--json-input` after_help note: []
```

### The two findings that matter more than the ratio

**1. The `--json-input` escape hatch never fires — and that is the bad news, not
the good news.** The hatch triggers on exactly one condition
(`unmappable()` = `type: "object"` with no enum). **No IDA parameter has
`type: "object"` anywhere** [measured]. So the spec's promise — "exceed the subset
and you degrade *visibly*" — is never exercised. The 54 class-C parameters do not
degrade visibly; they degrade **invisibly**, into untyped free-form string flags
that look exactly like a legitimately-mapped `type: "string"` parameter.

**2. Half the mapper is dead code against IDA** [measured]. A deep scan for
`$ref`, `$defs`, `definitions`, `anyOf`, `oneOf`, `allOf`, `enum`, `const`,
`additionalProperties`, `not`, `if`, `patternProperties`, `prefixItems`,
`nullable` over all 78 schemas returns **zero hits**. Concretely, against the W1-1
"supported subset" table:

| W1-1 claim | Reality in IDA |
|---|---|
| `Option<T>` as `type:[T,null]` | never occurs — schemars 1.2 emits bare `T` and omits the name from `required` |
| `Option<T>` as `anyOf` with null branch | never occurs |
| enum as `enum` | never occurs |
| enum as `oneOf` of `const` | never occurs |
| `$ref` into `$defs` | never occurs |
| nested object → `--json-input` | never occurs |

`deref()`, the `anyOf`/`oneOf` collapsing in `effective()`, `enum_values()`,
`unmappable()` and the whole `--json-input` path are all untouched by these 78
tools. Which also means **this survey cannot validate them**; the `$ref`-depth
question the brief asks ("how many levels can the mapper follow?") is answered by
reading, not by measurement: `deref()` is a **single, non-recursive** hop — a
`$ref` whose `$defs` target is itself a `$ref` returns the inner `$ref` object
unresolved, and everything downstream then sees no `type` and no `enum` and falls
into class C. JADX or Binary Ninja, whose arg types are more likely to be real
Rust enums, will exercise this. IDA will not.

---

## 2. Class C — constructs the mapper has no branch for [measured]

Three distinct constructs, 54 parameters, 45 tools. None of them panics; none of
them drops the parameter. All three land in the same place: `arg_for()` falls past
every `has_type(...)` guard to the trailing generic branch and emits
`Arg::new(name).long(kebab(name))` with **no `value_parser`**, and `to_arguments()`
sends `Value::String(raw)`.

### C-1. Schema with no `type` at all — 46 params, 44 tools

Rust source is `serde_json::Value` / `Option<Value>` carrying a `#[schemars(...)]`
description. schemars 1.2 renders that as a schema object with *only* a
description:

```json
"address": { "description": "Address(es) of function to decompile (string/number or array)" }
```

**What the mapper does** [read + measured]: `effective()` finds no `$ref`, no
`anyOf` → returns it unchanged. `types_of()` returns `[]`, so every
`has_type(inner, ...)` is false — including the `has_type(inner,"object")` guard
that would have triggered `--json-input`. Execution reaches the generic tail. Result
is a plain `--address <address>` string flag. `coerce()` sees no numeric type and no
`int_args` hint, so the value ships as a JSON **string**.

Measured round trip:

```
$ ida tool decompile --address 0x140001000
  -> decompile {"address":"0x140001000"}
```

Not wrong, as it happens — IDA's `value_to_addresses()` accepts `"0x140001000"` —
but it is an accident, not a decision. Three consequences:

- **The array half of the contract is unreachable.** 26 of these 46 say
  "string/number **or array**". The MCP surface takes `["0x1000","0x2000"]`;
  the derived flag is `ArgAction::Set`, single value. There is a workaround —
  `src/server/mod.rs:714` `value_to_strings()` splits a comma-separated string and
  also `serde_json`-parses a string that starts with `[` — so
  `--address "0x1000,0x2000"` works. But that is an IDA-side convention invisible
  to the schema, so a generic mapper cannot know it and `--help` will never say it.
- **Zero validation.** `--address not-an-address` is accepted by clap and fails
  much later, inside IDA.
- **It is indistinguishable from a well-typed `type: "string"` param** at every
  level: same `Arg`, same help, same `--help` rendering. Nothing anywhere tells the
  user, the implementer, or the mapper that a contract was lost.

All 46, tool.param:

```
addr_info.address              analyze_function.address       apply_types.address
basic_blocks.address           bookmark_add.address           callees.address
callers.address                callgraph.roots                comment_append.address
declare_stack.address          decompile.address              delete_stack.address
disasm.address                 disasm_function_at.address     dsc_add_region.address
export_funcs.addrs             find_bytes.patterns            find_insn_operands.patterns
find_insns.patterns            find_paths.end                 find_paths.start
function_at.address            get_bytes.address              get_global_value.query
get_string.address             get_u16.address                get_u32.address
get_u64.address                get_u8.address                 infer_types.address
int_convert.inputs             lookup_funcs.queries           lumina_apply.address
lumina_lookup.address          patch.address                  patch.bytes
patch_asm.address              pseudocode_at.address          read_struct.address
rename.address                 search.targets                 set_comments.address
stack_frame.address            xref_matrix.addrs              xrefs_from.address
xrefs_to.address
```

### C-2. The schema is the JSON literal `true` — 6 params, 1 tool

Bare `Option<serde_json::Value>` with **no** description. JSON Schema's "any value"
is the boolean schema `true`, and schemars emits exactly that:

```json
"properties": { "address": true, "end": true, "start": true,
                "function_address": true, "target": true, "value": true }
```

`sdk_mutation` only. This is not an object at all, so it is worth being precise
about what the Rust does [read]: every accessor in `cli.rs` goes through
`Value::get(...)`, which on a `Value::Bool` returns `None` rather than panicking.
So `deref` → passthrough, `types_of` → `[]`, `enum_values` → `[]`, `help_of` →
`None`. Same generic tail as C-1, plus **no help text at all**. No panic, no drop
— but the mapper has, strictly speaking, no idea what it just mapped.

### C-3. Array whose `items` schema is `true` — 2 params, 1 tool

`Option<Vec<Value>>`:

```json
"function_addresses": { "items": true, "type": "array" }
"string_addresses":   { "items": true, "type": "array" }
```

`sdk_mutation` only. `type: "array"` *is* recognised, so this one gets the right
`ArgAction::Append` + `num_args(1..)`. The unrecognised part is `items`:
`to_arguments()` does `effective(root, &items)` on `Value::Bool(true)` and
`coerce()` then produces strings. Measured:

```
$ ida tool sdk_mutation --action make_code --function-addresses 0x1000 0x2000
  -> sdk_mutation {"action":"make_code","function_addresses":["0x1000","0x2000"]}
```

Benign here (the handler parses string addresses), but it is the same silent
`→ String` fallback as C-1, and a `Vec<Value>` that genuinely wanted numbers or
objects would be mistyped without a word.

### Class C summary

| construct | params | tools | mapper's behaviour | verdict |
|---|---|---|---|---|
| C-1 schema with no `type` | 46 | 44 | free-form `--flag`, value → JSON string | silent, indistinguishable from a real string param |
| C-2 schema is `true` | 6 | 1 | free-form `--flag`, no help text | silent |
| C-3 `items: true` | 2 | 1 | correct `Append`, items → strings | silent |

---

## 3. Things that are *not* class C but still lose information

The mapper has a branch for these; it just doesn't use what the branch could see.

### 3a. `minimum` / `maximum` are never read — 90 integer params [measured]

Every paginating/limiting integer in the tree carries bounds, and none of them
reach clap. `cli.rs` reads `type`, `enum`/`oneOf`+`const`, `items`, `description`,
and nothing else — `minimum`, `maximum`, `format`, `pattern`, `minLength`,
`default` are all ignored.

```
$ ida tool survey_binary --detail not-a-detail-level --max-functions 99999999
  -> survey_binary {"detail":"not-a-detail-level","max_functions":99999999}
$ ida tool find_paths --start 0x1000 --end 0x2000 --max-paths 9999
  -> find_paths {"end":"0x2000","max_paths":9999,"start":"0x1000"}
```

`max_functions` is capped at 10000 in the schema, `max_paths` at 1024. Both sail
through. `clap::value_parser!(i64).range(min..=max)` would catch these at the CLI
boundary, which is where the user is.

The positive half is worth stating too: because `type: "integer"` *is* recognised,
`parse_int` runs and hex works — `--count 0x20` → `{"count":32}` [measured]. That is
the mapper doing its job.

### 3b. Zero enum validation anywhere — `PossibleValuesParser` count is 0 [measured]

Five parameters are enums in every sense except the schema's. They are declared
`Option<String>` in `src/server/requests.rs`, so the permitted values live only in
English prose:

| tool.param | description |
|---|---|
| `comment_append.scope` | "Comment scope: auto, func, or line" |
| `export_funcs.format` | "Export format (only json supported)" |
| `search.kind` | "Search type: text or imm (optional)" |
| `survey_binary.detail` | "'standard' (default) … 'minimal' skips it" |
| `tool_catalog.category` | "Filter by category: core, functions, disassembly, …" (14 values) |

```
$ ida tool comment_append --address 0x1000 --comment hi --scope nonsense-not-a-scope
  -> comment_append {"address":"0x1000","comment":"hi","scope":"nonsense-not-a-scope"}
```

This is **not** a mapper defect — `cli.rs` handles `enum` and `oneOf`+`const`
correctly; there is simply nothing to handle. Note the direction of the fix: this
is fixed in `requests.rs` (make them Rust enums), and doing so improves the *MCP*
surface too, since today an MCP client gets no validation either. The brief's worry
that "$defs would silently degrade enums to free-form strings" is real in principle
but moot here — IDA's enums are already free-form strings before the mapper sees
them.

### 3c. 25 flags with empty help text [measured]

`sdk_mutation`'s parameters carry no `#[schemars(description)]`, so `help_of()`
returns `None` for all 25. Rendered `--help` is 85 lines of flags with blank
descriptions:

```
Options:
      --action <action>

      --address <address>

      --bitfield
```

Cosmetic detail while you are in there: the value placeholder is the raw
snake_case arg id, so flags render as `--enum-name <enum_name>` — kebab flag,
snake placeholder.

---

## 4. The specific things the brief asked about

**`$ref` / `$defs`** [measured]: zero occurrences in all 78 schemas. No nesting to
test. `deref()` is a single non-recursive hop [read], so nested `$ref` would fail
open into class C — untestable here, but a live risk for the other two engines.

**`anyOf` on the input side** [measured]: none. The suspicion was well-founded but
the schema does not express it — the 26 "one address or an array of addresses"
parameters are `serde_json::Value`, i.e. C-1, not `anyOf`. `analyze_function.address`
is exactly this: description says "Target address(es) (string/number or array).
Max 32 targets per call", schema says `{"description": "..."}` and nothing more.
Had it been a real `anyOf` the mapper would have picked the **first non-null
branch** and dropped the rest [read], which is its own quiet contract loss — worth
knowing before someone "fixes" these into `anyOf`.

**Parameter-count distribution** [measured]: 0 params ×4, 1 ×17, 2 ×12, 3 ×8,
4 ×24, 5 ×4, 6 ×3, 7 ×2, then 9 (`open_idb`), 10 (`apply_types`),
14 (`analyze_function`), 25 (`sdk_mutation`). Rendered long help: `decompile`
13 lines, `open_idb` 37, `analyze_function` 52, `sdk_mutation` 85. Only
`sdk_mutation` is genuinely unusable, and its problem is the empty descriptions
(3c), not the count. `ida tool --help` listing 78 subcommands with their `title`
as the one-line about is fine.

**Name collisions** [measured]: clean, on every axis.
- No two parameters in one tool collide after `snake_case → kebab-case`.
- No parameter is named `help`, `version`, `json`, or `json_input` — so nothing
  collides with clap's built-ins or with the mapper's own `--json` / `--json-input`.
- No `no_x`/`x` pair that would collide with the hidden half of a boolean pair.
- No tool name collides with the real management commands
  (`mcp`/`serve`/`serve-http`/`probe`/`worker`); `EngineCli::command()` builds
  without panicking. Nor would the fallback `RESERVED` list refuse any of the 78.
- All 78 names are flat (no `.`), so the tree is one level: `ida tool <name>`.
  Worth a design decision — 78 flat subcommands under `tool` is a lot, and the
  catalog already groups them into 12 categories that would map onto `group.verb`.

**Positional candidates** — and a bug found while checking [measured]:

`CliHints.positional` is a `&[&str]`, but **its order is ignored**. `subcommand()`
registers args by iterating `properties`, and `properties` arrives from schemars
**alphabetically sorted** (`serde_json`'s `Map` is a `BTreeMap` on the IDA side),
while `required` preserves declaration order. So:

```
hint ["start", "end"] on find_paths: clap positional order = ["end", "start"]
  Usage: find_paths [OPTIONS] <END> <START>
  $ ida tool find_paths 0xSTART 0xEND -> {"end":"0xSTART","start":"0xEND"}
```

The two addresses are silently swapped. `find_paths` is directional, so this
returns a wrong answer rather than an error. Any tool with two or more positionals
is exposed; `find_paths` and `open_dsc` (`path`/`arch`/`module`, alphabetically
`arch` first) are the two live cases. Single-positional tools are unaffected and
work correctly:

```
$ ida tool decompile 0x140001000  -> {"address":"0x140001000"}
$ ida tool open_idb /tmp/cat      -> {"path":"/tmp/cat"}
```

Required-argument enforcement is correct: with no hatch present the mapper uses
`.required(true)`, and `ida tool decompile` / `ida tool open_dsc --path /c` both
error out [measured].

Suggested single-positional list — 39 tools have exactly one required parameter,
and in every case it is the obvious subject:

| positional | tools |
|---|---|
| `address` | `basic_blocks` `callees` `callers` `decompile` `disasm` `dsc_add_region` `get_string` `get_u8` `get_u16` `get_u32` `get_u64` `pseudocode_at` `read_struct` `stack_frame` `xrefs_from` `xrefs_to` |
| `name` | `disasm_by_name` `rename` `resolve_function` `tool_help` |
| `query` / `queries` | `find_string` `get_global_value` `lookup_funcs` `xrefs_to_string` |
| `patterns` | `find_bytes` `find_insns` `find_insn_operands` |
| `path` | `open_idb` |
| other | `callgraph.roots` `declare_type.decl` `dsc_add_dylib.module` `int_convert.inputs` `patch.bytes` `patch_asm.line` `sdk_mutation.action` `search.targets` `set_comments.comment` `task_status.task_id` `xref_matrix.addrs` |

Hold off on `find_paths` (`start`,`end`) and `open_dsc` (`path`,`arch`,`module`)
until the ordering bug is fixed.

---

## 5. Recommendations for whoever wires up all 78

Ordered by how much damage the omission does.

**1. Fix positional ordering before anyone declares a multi-positional tool.**
Iterate `d.cli.positional` in the hint's own order for positionals, then the
remaining `properties` for flags. Cheap, and it removes a wrong-answer bug that
no test would catch because both spellings parse.

**2. Make "schema with no `type`" a recognised construct rather than a fallthrough.**
This is the single highest-leverage change: it converts 54 invisible degradations
into visible ones, and it is the case the mapper's "never degrade silently"
rule was written for. Options, roughly in order of preference:

- Route it to the existing `--json-input` hatch — smallest change, honest, and it
  gives back the array form the MCP surface has and the CLI lost. Cost: 45 of 78
  tools grow a hatch, and the busiest ones (`decompile`, `disasm`, `xrefs_to`)
  become clumsier for the common single-address case.
- Better: emit the flag **and** name the parameter in `after_help` as
  unvalidated/single-valued, keeping `--json-input` available for the array form.
  Preserves ergonomics, restores honesty.
- Add an `int_args`-style hint that says "this untyped param is an address list",
  and give it `ArgAction::Append`. Most ergonomic, but it is per-tool hand-tuning
  ×46 and drifts the moment a schema changes — which is exactly what deriving
  the CLI from the schema exists to prevent.

Whatever is chosen, `unmappable()`'s current predicate is the thing to revisit: it
asks "is this an object?" when the question it means is "did I understand this?".
Inverting it — recognise a closed list of shapes, treat everything else as
unmapped — is what makes the guarantee hold for schemas nobody has seen yet.

**3. Honour `minimum` / `maximum`.** 90 parameters, mechanical, no hints needed:
`clap::value_parser!(i64).range(..)` when both bounds are present. Moves 90
validation failures from "IDA errors out several seconds later" to "clap rejects
the argument".

**4. Then fix IDA, not the mapper, for the rest.** Two changes on this side make
the derived CLI dramatically better and cost the mapper nothing:
- Turn the 5 prose enums into Rust enums (`scope`, `format`, `kind`, `detail`,
  `category`). The mapper already handles `enum` and `oneOf`+`const`; this
  immediately produces `PossibleValuesParser` and, incidentally, gives MCP clients
  the validation they also lack today.
- Replace `serde_json::Value` addresses with a named type. The natural shape is a
  `#[serde(untagged)] enum AddressSpec { One(String), Many(Vec<String>) }`, which
  is what the handlers already accept. Caution: that emits `anyOf`, and the mapper
  picks the first non-null branch and drops the rest [read] — so this needs
  recommendation 2 (or explicit `anyOf` support) landed first, or the contract
  loss just moves.

**5. Hardest tools, in order.** `sdk_mutation` (25 params, 8 class-C, no
descriptions, and it is really a dispatcher on `action` — a strong candidate for
`cli(none)` or for splitting into per-action tools). `analyze_function` (14 params,
5 boolean pairs defaulting to true — the `--no-x` half is what makes it work, so
that machinery must survive). `patch` (both `address` and `bytes` untyped, and
it mutates the database, so a silently mistyped argument is expensive).
`find_paths` and `open_dsc` (the positional-ordering trap). `apply_types`
(10 params, mutating, `address` untyped).

---

## Appendix — what was measured vs read

**Measured** (harness run against the live `tools/list` JSON, or a direct scan of
that JSON): the 78/271 counts; the A/B/C split; the 0 `--json-input`, 0
`PossibleValuesParser`, 3 `Append`, 34 `SetTrue` totals; the absence of `$ref`,
`$defs`, `anyOf`, `oneOf`, `enum`, `const` and friends; all round-trip
`argv → arguments` transcripts; required-argument enforcement; the positional
ordering swap; rendered `--help` line/byte counts; the name-collision checks and
the fact that `EngineCli::command()` builds without panicking; alphabetical
`properties` order vs declaration-order `required`.

**Read** (source inference, not exercised by these 78 schemas): that `deref()` is a
single non-recursive hop and nested `$ref` would fall through to class C; that
`effective()` picks the first non-null `anyOf`/`oneOf` branch and drops the others;
that `Value::get` on a `Value::Bool` returns `None` rather than panicking, which is
why the `true` schemas are handled quietly instead of loudly; IDA's
`value_to_strings()` comma/bracket splitting at `src/server/mod.rs:714`.

**Not verified.** The class-C parameters were not executed against a real database
— the local licence has no HEXX64 and the survey only needed `tools/list`. So
"IDA's handler accepts the string the CLI would send" is read from
`value_to_addresses` / `required_address`, not observed end to end.

Repro:

```sh
# schemas
IDADIR=/path/to/ida-9.4 \
RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,--allow-multiple-definition" \
  cargo build --release --bins
IDADIR=/path/to/ida-9.4 ./target/release/ida-headless-mcp --unsafe worker \
  < target/tmp/survey/req.jsonl > target/tmp/survey/worker_out.jsonl
# (the worker segfaults on stdin EOF after replying; both responses are already out)

# classification
cd ../vibrev && cargo run -p vibrev-kit --example ida_schema_survey -- \
  ../ida-headless-mcp/target/tmp/survey/tools.json
```

The harness is the only file this survey added to `vibrev/`. It is an `example`,
compiles with the crate's existing dependencies, and `cargo test -p vibrev-kit`
still passes 15/15.
