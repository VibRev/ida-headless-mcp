# Documentation

`ida-headless-mcp` is a multi-session headless IDA Pro MCP server. The
supervisor exposes the tool catalog; each database runs in its own IDA worker
process.

## Design

- **Supervisor / worker split** — MCP transports stay in the supervisor; IDA SDK calls stay in workers
- **Session IDs** — `idb_open` returns an opaque `database` handle required by every analysis tool
- **Streamable HTTP** — Multi-client support behind a mandatory bearer token, plus optional Host checks
- **Headless-only** — Debugger and GUI control are outside the public surface

## Contents

- [ARCHITECTURE.md](ARCHITECTURE.md) - Supervisor/worker design
- [MIGRATION.md](MIGRATION.md) - Migrating from the old ida-pro-mcp-compatible names
- [TOOLS.md](TOOLS.md) - Worker tool catalog
- [TRANSPORTS.md](TRANSPORTS.md) - Stdio vs Streamable HTTP
- [BUILDING.md](BUILDING.md) - Build from source
- [TESTING.md](TESTING.md) - Running tests
