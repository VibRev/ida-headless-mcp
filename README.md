# ida-headless-mcp

English | [简体中文](README.zh-CN.md)

Rust-native, multi-session headless [IDA Pro](https://hex-rays.com/ida-pro) MCP server.

This project is a derivative of [blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs), rewritten around an explicit supervisor/worker split and pinned to the [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) public contract. It is not a drop-in replacement for the upstream Homebrew/Scoop packages, and it is not an official Hex-Rays product.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What this project adds

- One supervisor process owns MCP stdio or Streamable HTTP.
- Each open database gets its own IDA worker process; a crash takes down one session, not the server.
- Session lifecycle is explicit: `idb_open`, `idb_list`, `idb_close`, `server_health`, plus analysis tools that all require a `database` session ID.
- 85 tools by default, 86 with `--unsafe`, in 12 categories.
- Headless-only: debugger and GUI control stay out of the public surface.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/MIGRATION.md](docs/MIGRATION.md).

## Prerequisites

- IDA Pro 9.2, 9.3, or 9.4 with a valid license
- Rust 1.95+ (source builds only; set by vibrev-kit, not by this crate)
- LLVM/Clang for the C++ bindings (source builds only)

Release builds never ship IDA, the SDK, or IDA runtime libraries. You must already have a licensed IDA install on the same platform and architecture.

## Install

There is no package-manager distribution — no Homebrew tap, no Scoop bucket, no snap. Two paths:

1. **Prebuilt archive.** Download from [Releases](https://github.com/fuqiuluo/ida-headless-mcp/releases), verify against `checksums.txt`, and put the executable on your `PATH`.
2. **Build from source** (below) — the only option for any other platform or architecture.

Archives are named `ida-headless-mcp_<version>_ida-<minor>_<OS>_<arch>`, with `.tar.gz` on Unix and `.zip` on Windows. `<OS>` is `Linux`, `macOS`, or `Windows`. Each release publishes three IDA minors (9.2, 9.3, 9.4) for three platform pairs — `Linux_x86_64`, `macOS_arm64`, `Windows_x86_64` — so nine archives in total. Each one carries the executable plus `README.md`, `LICENSE`, and `NOTICE`.

Pick the archive whose IDA minor matches your installed IDA. The binary checks the loaded IDA version before it opens a database: once either side is 9.4 the minor has to match exactly, because `idalib` reconstructs IDA-internal layouts by hand and 9.4 moved one of them. Below 9.4 only the major is compared (IDA 9.3 reports its product version as 9.0), but matching the minor is still the right habit.

## Build

See [docs/BUILDING.md](docs/BUILDING.md). Each IDA minor has its own manifest; pick exactly one:

```bash
# IDA 9.4 (default)
IDADIR=/path/to/ida-9.4 cargo build --release

# IDA 9.3
IDADIR=/path/to/ida-9.3 cargo build --release \
  --manifest-path sdk/ida-93/Cargo.toml

# IDA 9.2
IDADIR=/path/to/ida-9.2 cargo build --release \
  --manifest-path sdk/ida-92/Cargo.toml
```

The 9.4 binary is under `target/release`; 9.2 and 9.3 use their manifest-local
`sdk/ida-*/target/release` directories. Windows adds the `.exe` suffix. The 9.2
and 9.3 builds need one extra linker flag — see [docs/BUILDING.md](docs/BUILDING.md).

`just --list` shows the repo's build and test recipes; [docs/TESTING.md](docs/TESTING.md) explains which ones need a licensed IDA.

## Platform setup

The process links against IDA at runtime. Point it at your install if it is not in a default location:

| Platform | Typical path | Runtime hint |
|----------|--------------|--------------|
| Linux | `~/ida-pro-9.4` or `/opt/ida-pro-9.4` | `IDADIR` or `LD_LIBRARY_PATH` |
| macOS | `/Applications/IDA Professional 9.4.app/Contents/MacOS` | `IDADIR` or `DYLD_LIBRARY_PATH` |
| Windows | `C:\Program Files\IDA Professional 9.4` | Put the exe next to `ida.dll`, or set `IDADIR` and add that directory to `PATH` |

```bash
# Linux / macOS
export IDADIR=/path/to/ida
./target/release/ida-headless-mcp
```

```powershell
# Windows
$env:IDADIR = "C:\Program Files\IDA Professional 9.4"
.\target\release\ida-headless-mcp.exe
```

## Configure an MCP client

Running the binary with no subcommand is the same as `serve`: a stdio supervisor. After the binary is on `PATH` (or use the absolute path):

### Claude Code

```bash
claude mcp add ida -- ida-headless-mcp
```

### Codex CLI

```bash
codex mcp add ida -- ida-headless-mcp
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ida": {
      "command": "ida-headless-mcp",
      "env": {
        "IDADIR": "/path/to/ida"
      }
    }
  }
}
```

## Usage

The supervisor returns an opaque session ID from `idb_open`. Pass that ID as `database` to every analysis tool, then close the session when finished.

```
idb_open(input_path: "~/samples/malware")
idb_list()
list_funcs(database: "<session_id>", offset: 0, limit: 20)
find_string(database: "<session_id>", query: "libc")
disasm(database: "<session_id>", address: "0x100000f00")
xrefs_to(database: "<session_id>", address: "0x100000f00")
decompile(database: "<session_id>", address: "0x100000f00")
idb_close(database: "<session_id>")
```

Notes that save a round trip:

- `input_path` may be a raw binary (Mach-O/ELF/PE) or an existing `.i64`/`.idb`. Opening the same canonical path twice returns the session that already exists instead of a second worker.
- Sessions are reaped after `idle_ttl_sec` seconds idle (default 600); pass `0` to disable.
- `idb_open` takes a `mode`: `prefer_headless` (default), `force_headless`, and `prefer_gui` all yield a headless worker; `force_gui` returns a stable unsupported-mode error, because this build is headless-only.
- `--max-databases` (default 4) caps how many worker processes the stdio supervisor keeps alive at once.
- `server_health` reports on the supervisor without touching a database.

Coming from the previous `ida-pro-mcp`-compatible tool names? See the mapping table in [docs/MIGRATION.md](docs/MIGRATION.md).

### Streamable HTTP

```bash
./target/release/ida-headless-mcp serve-http --bind 127.0.0.1:8765
```

Unlike stdio, this opens a listener, so **every request needs a bearer token** — there is no flag that turns it off. The token lives in `$VIBREV_HOME/token`, or `~/.vibrev/token` when that is unset (mode `0600`, generated on first use and reused afterwards); `--token-file` moves it. On startup the server prints a security banner and a paste-able client-config snippet:

```jsonc
"ida-headless-mcp": {
  "type": "http",
  "url": "http://127.0.0.1:8765/mcp",
  "headers": { "Authorization": "Bearer vbr_…" }
}
```

The token is elided from that snippet when stderr is not a terminal, so redirected logs and CI output do not leak it; read it back with `head -n1 ~/.vibrev/token`.

Here `--max-workers` (default 4) — not `--max-databases` — sizes the child worker pool. See [docs/TRANSPORTS.md](docs/TRANSPORTS.md) for authentication, Origin/Host checks, session keep-alive, and the rest of the pool flags.

### Bundled skills

The binary carries an IDAPython reference skill (105 files, compressed into the
executable) that teaches a model the `ida_*` API the tool surface sits on top of.
It is packed at build time from `skills/` and written back out byte for byte:

```bash
ida-headless-mcp skills list
ida-headless-mcp skills export --dir ~/.claude/skills
```

Neither command opens a database or needs an IDA license — the answer is baked
into the binary. `vibrev install ida` calls them for you and puts the result
where Claude Code reads it; see `vibrev skill --help`. Only Claude Code has a
skill mechanism, so other clients get the MCP server without this part.

### Tool filtering

The default catalog advertises every available tool except `run_script`, which executes arbitrary IDAPython inside the worker. `--unsafe` (or `IDA_MCP_UNSAFE=true`) enables it — that is the only tool the flag gates.

To narrow the surface instead:

- `--toolsets` keeps only the named categories: `core`, `functions`, `disassembly`, `decompile`, `xrefs`, `control_flow`, `memory`, `search`, `metadata`, `types`, `editing`, `scripting`.
- `--tools` adds individual tools back on top of `--toolsets`.
- `--exclude-tools` removes tools; exclusion always wins.
- `--read-only` keeps only tools that declare `readOnlyHint`, so it tracks the catalog rather than a hand-kept list.

Each has an environment mirror (`IDA_MCP_TOOLSETS`, `IDA_MCP_TOOLS`, `IDA_MCP_EXCLUDE_TOOLS`, `IDA_MCP_READ_ONLY`).

### Lumina

Automatic Lumina lookup is disabled unless you opt in:

```bash
ida-headless-mcp --allow-lumina
```

The equivalent environment setting is `IDA_MCP_ALLOW_LUMINA=true`. The isolated IDA user profile used by this server does not change the normal IDA GUI profile.

## Limitations

- **You bring your own IDA.** No archive here contains IDA, its SDK, or its runtime libraries, and none of them will run without a licensed install.
- **The decompiler-backed tools need Hex-Rays.** Without a decompiler license the worker reports "Hex-Rays decompiler is not available" at warm-up, and `decompile`, `pseudocode_at`, `diff_before_after` and the pseudocode part of `analyze_function` cannot answer. Everything built on disassembly still works.
- **Prebuilt binaries cover three platform pairs only** — Linux x86_64, macOS arm64, Windows x86_64. Anything else means building from source.
- **A binary is tied to one IDA minor.** Mixing a 9.4 build with a non-9.4 runtime, or the reverse, is rejected before any database opens.
- **Headless-only.** There is no debugger surface and no GUI control; `force_gui` is an error, not a fallback.
- **HTTP is authenticated, always.** There is no anonymous mode, so a client that cannot send an `Authorization` header cannot use this transport.

## Docs

- [docs/TOOLS.md](docs/TOOLS.md) — worker tool catalog
- [docs/TRANSPORTS.md](docs/TRANSPORTS.md) — stdio vs Streamable HTTP
- [docs/BUILDING.md](docs/BUILDING.md) — build from source
- [docs/TESTING.md](docs/TESTING.md) — running tests
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — supervisor/worker design
- [docs/MIGRATION.md](docs/MIGRATION.md) — migrating from the old `ida-pro-mcp`-compatible tool names

## Attribution

Substantial portions of the IDA worker, MCP tool implementations, and build glue come from [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) by **blacktop**, MIT License.

The multi-database session model (`idb_open` / `idb_list` / `idb_close` plus a `database` argument on every analysis tool) follows [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) by **Duncan Ogilvie** and contributors, MIT License. This project no longer implements that project's tool contract; see [docs/MIGRATION.md](docs/MIGRATION.md).

IDA bindings come from [idalib](https://github.com/blacktop/idalib) (`MIT OR Apache-2.0`).

Full notices are in [NOTICE](NOTICE).

## License

MIT. Copyright (c) 2026 **blacktop**. Copyright (c) 2026 **fuqiuluo** and ida-headless-mcp contributors.

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
