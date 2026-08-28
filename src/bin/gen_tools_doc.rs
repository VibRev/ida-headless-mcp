//! Regenerates docs/TOOLS.md from the live tool catalog.
//!
//! Usage: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`

use ida_mcp::server::catalog::{self, ToolCategory};
use ida_mcp::supervisor::server::{is_routable_tool, SESSION_TOOLS, UNSAFE_TOOLS};
use std::fmt::Write as _;

fn category_title(cat: ToolCategory) -> &'static str {
    match cat {
        ToolCategory::Core => "Core",
        ToolCategory::Functions => "Functions",
        ToolCategory::Disassembly => "Disassembly",
        ToolCategory::Decompile => "Decompile",
        ToolCategory::Xrefs => "Xrefs",
        ToolCategory::ControlFlow => "Control Flow",
        ToolCategory::Memory => "Memory",
        ToolCategory::Search => "Search",
        ToolCategory::Metadata => "Metadata",
        ToolCategory::Types => "Types",
        ToolCategory::Editing => "Editing",
        ToolCategory::Scripting => "Scripting",
    }
}

fn main() {
    let tool_count = catalog::native_tool_names().count();

    let mut out = String::new();
    let _ = writeln!(out, "# Tools\n");
    let _ = writeln!(
        out,
        "> Auto-generated from the `#[tool]` router. Do not edit by hand."
    );
    let _ = writeln!(
        out,
        "> Regenerate with: `cargo run --bin gen_tools_doc -- docs/TOOLS.md`.\n"
    );

    let _ = writeln!(out, "## Discovery Workflow\n");
    let _ = writeln!(
        out,
        "- `tools/list` returns the full tool set (currently {tool_count} tools)"
    );
    let _ = writeln!(
        out,
        "- `tool_catalog(query=...)` searches all tools by intent"
    );
    let _ = writeln!(
        out,
        "- `tool_help(name=...)` returns the full description and schema"
    );
    let _ = writeln!(out);
    let with_output_schema = catalog::native_tools()
        .iter()
        .filter(|tool| tool.output_schema.is_some())
        .count();
    let _ = writeln!(
        out,
        "Every tool advertises a `title` and safety `annotations`. `outputSchema` is \
         being restored tool by tool ({with_output_schema}/{tool_count} so far); the \
         \"Output schema\" column below says which ones have it.\n"
    );

    let _ = writeln!(out, "## Sessions\n");
    let _ = writeln!(
        out,
        "The default entry point is the supervisor: it owns the session table, so \
         database lifecycle runs through its own tools ({}) rather than the \
         worker-local `open_idb` / `open_dsc` / `close_idb`. Every other tool takes \
         the `database` session ID returned by `idb_open`.\n",
        SESSION_TOOLS
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        "Tools hidden unless the server runs with `--unsafe`: {}.\n",
        UNSAFE_TOOLS
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    for &cat in ToolCategory::all() {
        let tools = catalog::tools_in_category(cat).collect::<Vec<_>>();
        if tools.is_empty() {
            continue;
        }
        let _ = writeln!(out, "## {} (`{}`)\n", category_title(cat), cat.as_str());
        let _ = writeln!(out, "{}", cat.description());
        let _ = writeln!(
            out,
            "\n| Tool | Title | Supervisor | Output schema | Description |"
        );
        let _ = writeln!(
            out,
            "|------|-------|------------|---------------|-------------|"
        );
        for name in tools {
            let routed = if is_routable_tool(name) {
                "routed"
            } else {
                "worker-local"
            };
            let tool = catalog::native_tool(name);
            let title = tool
                .as_ref()
                .and_then(|tool| tool.title.clone())
                .unwrap_or_default();
            let output_schema = if tool
                .as_ref()
                .is_some_and(|tool| tool.output_schema.is_some())
            {
                "yes"
            } else {
                "-"
            };
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {} |",
                name,
                title,
                routed,
                output_schema,
                catalog::short_description_of(name).unwrap_or_default()
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Notes\n");
    let _ = writeln!(
        out,
        "- Many tools accept a single value or array (e.g., `\"0x1000\"` or `[\"0x1000\", \"0x2000\"]`)"
    );
    let _ = writeln!(
        out,
        "- String inputs may be comma-separated: `\"0x1000, 0x2000\"`"
    );
    let _ = writeln!(out, "- Addresses accept hex (`0x1000`) or decimal (`4096`)");
    let _ = writeln!(
        out,
        "- Raw binaries are auto-analyzed on first open; `.i64` is saved alongside the input and reused on later raw-path opens unless `rebuild=true`"
    );

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        if let Err(err) = std::fs::write(&args[1], out) {
            eprintln!("failed to write {}: {}", args[1], err);
            std::process::exit(1);
        }
    } else {
        print!("{out}");
    }
}
