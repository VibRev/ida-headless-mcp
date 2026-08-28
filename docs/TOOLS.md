# Tools

> Auto-generated from the `#[tool]` router. Do not edit by hand.
> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.

## Discovery Workflow

- `tools/list` returns the full tool set (currently 85 tools)
- `tool_catalog(query=...)` searches all tools by intent
- `tool_help(name=...)` returns the full description and schema

Every tool advertises a `title` and safety `annotations`. `outputSchema` is being restored tool by tool (85/85 so far); the "Output schema" column below says which ones have it.

## Sessions

The default entry point is the supervisor: it owns the session table, so database lifecycle runs through its own tools (`idb_open`, `idb_list`, `idb_close`, `server_health`) rather than the worker-local `open_idb` / `open_dsc` / `close_idb`. Every other tool takes the `database` session ID returned by `idb_open`.

Tools hidden unless the server runs with `--unsafe`: `run_script`.

## Core (`core`)

Database open/close, analysis status, and discovery tools

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `analysis_status` | Auto-analysis readiness | routed | yes | Report auto-analysis status (auto_is_ok, auto_state). |
| `analyze_funcs` | Run full auto-analysis | routed | yes | Run IDA auto-analysis to completion. |
| `close_idb` | Release the open database | worker-local | yes | Close the currently open IDA database. |
| `dsc_add_dylib` | Map a dylib out of the shared cache | routed | yes | Load an additional dylib into an open DSC database (requires prior open_dsc). |
| `dsc_add_region` | Map a shared-cache address range | routed | yes | Load a DSC region by address into an open DSC database (data/GOT/stub areas; one address per call; requires prior open_dsc). |
| `idb_meta` | Database fingerprint | routed | yes | Get IDB metadata (ida-pro-mcp compatibility) |
| `load_debug_info` | Attach external symbols | routed | yes | Load external debug info (e.g., DWARF/dSYM) into the current database. |
| `open_dsc` | Open a dyld shared cache | worker-local | yes | Open a dyld_shared_cache and load a single dylib (e.g. |
| `open_idb` | Open a binary or database | worker-local | yes | Open an IDA database (.i64/.idb) or raw binary (Mach-O/ELF/PE). |
| `recent_operations` | Recent foreground operation log | routed | yes | Inspect recent foreground operation history. |
| `task_status` | Background task progress | routed | yes | Check the status of a background task (e.g. |
| `tool_catalog` | Browse the toolbox | routed | yes | Discover available tools by query or category. |
| `tool_help` | Full docs for one tool | routed | yes | Get full documentation for a tool including description, parameters schema, and example. |

## Functions (`functions`)

List, search, and resolve functions

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `analyze_component` | Related functions as a group | routed | yes | Analyze related functions as a group: compact per-function summaries, the internal call graph, shared globals, and interface vs internal functions. |
| `analyze_function` | Complete dossier on one function | routed | yes | Everything about one function in a single call: disassembly, decompiler pseudocode, callers, callees, the strings it references, its stack frame and its control-flow graph. |
| `func_profile` | Cheap single-function summary | routed | yes | A cheaper look at one function than analyze_function: callers, callees, basic blocks, cyclomatic complexity and string refs, with no decompile and no instruction listing. |
| `function_at` | Enclosing function of an address | routed | yes | Get the function that contains an address |
| `list_funcs` | Browse every function (alias) | routed | yes | List functions (ida-pro-mcp compatible alias). |
| `list_functions` | Browse every function | routed | yes | List all functions in the database (paginated). |
| `lookup_funcs` | Batch function lookup | routed | yes | Lookup functions by name or address (batch) |
| `resolve_function` | Function address by name | routed | yes | Resolve a function name to its address |

## Disassembly (`disassembly`)

Disassemble code at addresses

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `disasm` | Instructions at an address | routed | yes | Get disassembly at an address |
| `disasm_by_name` | Instructions of a named function | routed | yes | Get disassembly for a function by name |
| `disasm_function_at` | Whole-function instruction listing | routed | yes | Disassemble the function containing an address |

## Decompile (`decompile`)

Decompile functions to pseudocode (requires Hex-Rays)

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `decompile` | C pseudocode for a function | routed | yes | Decompile a function using Hex-Rays (if available) |
| `pseudocode_at` | Pseudocode for one address range | routed | yes | Get decompiled pseudocode at a specific address or address range. |

## Xrefs (`xrefs`)

Cross-reference analysis (xrefs to/from)

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `trace_data_flow` | Multi-hop xref walk | routed | yes | Walk xrefs forward (xrefs_from) or backward (xrefs_to) from one address by BFS. |
| `xref_matrix` | Reference matrix across addresses | routed | yes | Compute xref matrix for a set of addresses |
| `xrefs_from` | Outgoing references | routed | yes | Get cross-references FROM an address (what this address references). |
| `xrefs_to` | Incoming references | routed | yes | Get cross-references TO an address (who references this address). |
| `xrefs_to_field` | References to a struct field | routed | yes | Get xrefs to a struct field. |
| `xrefs_to_string` | References to matching strings | routed | yes | Find strings and return xrefs to each match. |

## Control Flow (`control_flow`)

Basic blocks, call graphs, control flow

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `basic_blocks` | Control-flow graph nodes | routed | yes | Get basic blocks of a function (control flow graph nodes). |
| `callees` | Functions this one calls | routed | yes | Get functions called BY a function (callees/children in call graph). |
| `callers` | Functions calling this one | routed | yes | Get functions that CALL a function (callers/parents in call graph). |
| `callgraph` | Call graph around a root | routed | yes | Build a callgraph rooted at an address |
| `find_paths` | Control-flow paths between two points | routed | yes | Find paths between two addresses (CFG) |

## Memory (`memory`)

Read bytes, strings, and data

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `get_bytes` | Raw bytes as hex | routed | yes | Read raw bytes from an address as hex string |
| `get_global_value` | Value behind a global symbol | routed | yes | Get global value(s) by name or address |
| `get_int` | Typed integer read | routed | yes | Read an integer of any width, signedness and byte order. |
| `get_string` | String stored at an address | routed | yes | Read string(s) at address(es) |
| `get_u16` | 16-bit reads | routed | yes | Read u16 values at address(es) |
| `get_u32` | 32-bit reads | routed | yes | Read u32 values at address(es) |
| `get_u64` | 64-bit reads | routed | yes | Read u64 values at address(es) |
| `get_u8` | 8-bit reads | routed | yes | Read u8 values at address(es) |
| `int_convert` | Integer base and byte-order converter | routed | yes | Convert integers between bases |

## Search (`search`)

Search for bytes, strings, patterns

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `analyze_strings` | Strings with their references | routed | yes | Analyze strings with xrefs (ida-pro-mcp compatibility). |
| `find_bytes` | Byte-pattern scan | routed | yes | Find byte patterns (ida-pro-mcp compatibility). |
| `find_insn_operands` | Operand pattern scan | routed | yes | Find instruction operands. |
| `find_insns` | Mnemonic sequence scan | routed | yes | Find instruction sequences by mnemonic. |
| `find_string` | String lookup by text | routed | yes | Find strings matching a query (supports exact/case-insensitive options). |
| `make_signature` | Unique byte signature | routed | yes | Build a byte signature that identifies an address. |
| `search` | Text and immediate scan | routed | yes | Search for text or immediates (ida-pro-mcp compatibility). |
| `strings` | Browse extracted strings | routed | yes | List strings in the database with pagination and optional filter. |

## Metadata (`metadata`)

Database info, segments, imports, exports

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `addr_info` | What lives at an address | routed | yes | Get address context (segment, function, nearest symbol) |
| `entrypoints` | Program entry points | routed | yes | Get entry point addresses of the binary |
| `export_funcs` | Bulk function export | routed | yes | Export functions (ida-pro-mcp compatibility) |
| `exports` | Public symbol table | routed | yes | List exports/names (public symbols) with pagination. |
| `imports` | External symbol table | routed | yes | List imports (external symbols) with pagination. |
| `list_globals` | Browse non-function symbols | routed | yes | List global names (non-function symbols). |
| `lumina_lookup` | Preview Lumina metadata | routed | yes | Look up Lumina metadata for a function without applying it |
| `segments` | Memory layout | routed | yes | List all segments in the database with their permissions and types |
| `survey_binary` | First look at an unknown binary | routed | yes | Orient yourself in an unfamiliar binary with one call. |

## Types (`types`)

Types, structs, and stack variable info

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `apply_types` | Give a location a type | routed | yes | Apply a type to an address, or to a stack variable with stack_offset/stack_name. |
| `declare_stack` | Add a stack variable | routed | yes | Declare a stack variable in a function frame. |
| `declare_type` | Add a local type | routed | yes | Declare a type in the local type library. |
| `delete_stack` | Remove a stack variable | routed | yes | Delete a stack variable from a function frame. |
| `infer_types` | Guess the type at a location | routed | yes | Infer/guess type at an address |
| `local_types` | Browse the local type library | routed | yes | List local types |
| `read_struct` | Struct instance values in memory | routed | yes | Read values of a struct instance at an address. |
| `search_structs` | Struct lookup by name | routed | yes | Search structs by name |
| `stack_frame` | Frame layout of a function | routed | yes | Get stack frame info |
| `struct_info` | Struct definition detail | routed | yes | Get info about a struct by ordinal or name. |
| `structs` | Browse structures and unions | routed | yes | List structs in the database with pagination and optional filter. |

## Editing (`editing`)

Patching, renaming, and comment editing

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `bookmark_add` | Mark an address | routed | yes | Add or replace a bookmark at an address |
| `comment_append` | Add to an existing comment | routed | yes | Append a line or function comment |
| `diff_before_after` | Side-by-side decompile after an edit | routed | yes | Rename a function, apply a prototype, or set a comment, then compare Hex-Rays output before and after. |
| `lumina_apply` | Pull Lumina metadata in | routed | yes | Pull and apply Lumina metadata to a function |
| `patch` | Overwrite bytes | routed | yes | Patch bytes at an address |
| `patch_asm` | Assemble over an instruction | routed | yes | Patch instructions with assembly text |
| `put_int` | Typed integer write | routed | yes | Write an integer of any width, signedness and byte order. |
| `rename` | Give a symbol a new name | routed | yes | Rename symbols |
| `sdk_mutation` | Low-level database edit | routed | yes | Execute a low-level IDA SDK database mutation |
| `set_comments` | Replace comments at an address | routed | yes | Set comments at an address |

## Scripting (`scripting`)

Execute Python scripts via IDAPython

| Tool | Title | Supervisor | Output schema | Description |
|------|-------|------------|---------------|-------------|
| `run_script` | Run IDAPython inside the database | routed | yes | Execute IDAPython in the open database. |

## Notes

- Many tools accept a single value or array (e.g., `"0x1000"` or `["0x1000", "0x2000"]`)
- String inputs may be comma-separated: `"0x1000, 0x2000"`
- Addresses accept hex (`0x1000`) or decimal (`4096`)
- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input and reused on later raw-path opens unless `rebuild=true`
