//! Native tool catalog.
//!
//! [`IdaMcpServer::tool_router`] is the single source of truth for tool names
//! and input schemas. It merges the per-domain routers in `tools/`. Nothing
//! in this module re-declares them: names, descriptions and schemas are read
//! back out of that router, so a new `#[tool]` shows up in `tools/list`, in
//! `--tools`, and in the supervisor's routing table without extra bookkeeping.
//!
//! The only hand-maintained data here is the tool -> category map that backs
//! `--toolsets` and `tool_catalog`. `every_native_tool_has_a_category` fails
//! the test suite when a tool is added without one, so the map cannot silently
//! drift out of sync with the router it categorizes.

use super::{apply_tool_metadata, IdaMcpServer};
use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::LazyLock;

/// Tool category for grouping related tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Core database operations and server introspection.
    Core,
    /// Function navigation and discovery.
    Functions,
    /// Disassembly tools.
    Disassembly,
    /// Decompilation tools (requires Hex-Rays).
    Decompile,
    /// Cross-reference analysis.
    Xrefs,
    /// Control flow and call graph analysis.
    ControlFlow,
    /// Memory and data reading.
    Memory,
    /// Search and pattern matching.
    Search,
    /// Metadata and structure info.
    Metadata,
    /// Type/struct/stack information and type application.
    Types,
    /// Editing and patching operations.
    Editing,
    /// Scripting/eval helpers.
    Scripting,
}

impl ToolCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Functions => "functions",
            Self::Disassembly => "disassembly",
            Self::Decompile => "decompile",
            Self::Xrefs => "xrefs",
            Self::ControlFlow => "control_flow",
            Self::Memory => "memory",
            Self::Search => "search",
            Self::Metadata => "metadata",
            Self::Types => "types",
            Self::Editing => "editing",
            Self::Scripting => "scripting",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Core => "Database open/close, analysis status, and discovery tools",
            Self::Functions => "List, search, and resolve functions",
            Self::Disassembly => "Disassemble code at addresses",
            Self::Decompile => "Decompile functions to pseudocode (requires Hex-Rays)",
            Self::Xrefs => "Cross-reference analysis (xrefs to/from)",
            Self::ControlFlow => "Basic blocks, call graphs, control flow",
            Self::Memory => "Read bytes, strings, and data",
            Self::Search => "Search for bytes, strings, patterns",
            Self::Metadata => "Database info, segments, imports, exports",
            Self::Types => "Types, structs, and stack variable info",
            Self::Editing => "Patching, renaming, and comment editing",
            Self::Scripting => "Execute Python scripts via IDAPython",
        }
    }

    pub fn all() -> &'static [ToolCategory] {
        &[
            Self::Core,
            Self::Functions,
            Self::Disassembly,
            Self::Decompile,
            Self::Xrefs,
            Self::ControlFlow,
            Self::Memory,
            Self::Search,
            Self::Metadata,
            Self::Types,
            Self::Editing,
            Self::Scripting,
        ]
    }
}

impl FromStr for ToolCategory {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let normalized = input.trim().to_lowercase().replace(['-', ' '], "_");
        match normalized.as_str() {
            "core" => Ok(Self::Core),
            "functions" | "function" => Ok(Self::Functions),
            "disassembly" | "disasm" => Ok(Self::Disassembly),
            "decompile" | "decompiler" => Ok(Self::Decompile),
            "xrefs" | "xref" | "references" => Ok(Self::Xrefs),
            "control_flow" | "controlflow" | "cfg" => Ok(Self::ControlFlow),
            "memory" | "data" => Ok(Self::Memory),
            "search" => Ok(Self::Search),
            "metadata" | "meta" | "info" => Ok(Self::Metadata),
            "types" | "type" | "structs" => Ok(Self::Types),
            "editing" | "edit" => Ok(Self::Editing),
            "scripting" | "script" | "python" => Ok(Self::Scripting),
            _ => Err(()),
        }
    }
}

/// Category of a native tool, or `None` when the name is not a native tool.
///
/// Keep this exhaustive: `every_native_tool_has_a_category` enforces it.
pub fn category_of(name: &str) -> Option<ToolCategory> {
    Some(match name {
        // Core
        "analysis_status" | "analyze_funcs" | "close_idb" | "dsc_add_dylib" | "dsc_add_region"
        | "idb_meta" | "load_debug_info" | "open_dsc" | "open_idb" | "recent_operations"
        | "task_status" | "tool_catalog" | "tool_help" => ToolCategory::Core,
        // Functions
        "analyze_component" | "analyze_function" | "func_profile" | "function_at"
        | "list_funcs" | "list_functions" | "lookup_funcs" | "resolve_function" => {
            ToolCategory::Functions
        }
        // Disassembly
        "disasm" | "disasm_by_name" | "disasm_function_at" => ToolCategory::Disassembly,
        // Decompile
        "decompile" | "pseudocode_at" => ToolCategory::Decompile,
        // Xrefs
        "trace_data_flow" | "xref_matrix" | "xrefs_from" | "xrefs_to" | "xrefs_to_field"
        | "xrefs_to_string" => ToolCategory::Xrefs,
        // Control flow
        "basic_blocks" | "callees" | "callers" | "callgraph" | "find_paths" => {
            ToolCategory::ControlFlow
        }
        // Memory
        "get_bytes" | "get_global_value" | "get_int" | "get_string" | "get_u16" | "get_u32"
        | "get_u64" | "get_u8" | "int_convert" => ToolCategory::Memory,
        // Search
        "analyze_strings" | "find_bytes" | "find_insn_operands" | "find_insns" | "find_string"
        | "make_signature" | "search" | "strings" => ToolCategory::Search,
        // Metadata
        "addr_info" | "entrypoints" | "export_funcs" | "exports" | "imports" | "list_globals"
        | "lumina_lookup" | "segments" | "survey_binary" => ToolCategory::Metadata,
        // Types
        "apply_types" | "declare_stack" | "declare_type" | "delete_stack" | "infer_types"
        | "local_types" | "read_struct" | "search_structs" | "stack_frame" | "struct_info"
        | "structs" => ToolCategory::Types,
        // Editing
        "bookmark_add" | "comment_append" | "diff_before_after" | "lumina_apply" | "patch"
        | "patch_asm" | "put_int" | "rename" | "sdk_mutation" | "set_comments" => {
            ToolCategory::Editing
        }
        // Scripting
        "run_script" => ToolCategory::Scripting,
        _ => return None,
    })
}

/// Native tools exactly as advertised on `tools/list`: schemas normalized for
/// downstream bridges and safety annotations attached. Sorted by name.
static NATIVE_TOOLS: LazyLock<Vec<Tool>> = LazyLock::new(|| {
    IdaMcpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|mut tool| {
            vibrev_kit::schema::normalize_tool(&mut tool);
            apply_tool_metadata(tool)
        })
        .collect()
});

/// `'static` names for the native tools. The worker transport wants
/// `&'static str` tool names, and the router hands out `Cow<'static, str>`
/// whose borrowed payload is exactly the literal in the `#[tool]` attribute.
static NATIVE_TOOL_NAMES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    NATIVE_TOOLS
        .iter()
        .map(|tool| match tool.name {
            std::borrow::Cow::Borrowed(name) => name,
            // Not reachable for macro-generated tools, but leaking a handful
            // of process-lifetime names beats panicking on a future rmcp that
            // materializes owned names.
            std::borrow::Cow::Owned(ref name) => &*Box::leak(name.clone().into_boxed_str()),
        })
        .collect()
});

/// Full native tool catalog (unfiltered).
pub fn native_tools() -> Vec<Tool> {
    NATIVE_TOOLS.clone()
}

/// Names of all native tools, sorted.
pub fn native_tool_names() -> impl Iterator<Item = &'static str> {
    NATIVE_TOOL_NAMES.iter().copied()
}

/// Resolve a caller-supplied name to the interned native tool name.
pub fn native_tool_name(name: &str) -> Option<&'static str> {
    native_tool_names().find(|candidate| *candidate == name)
}

/// Single native tool definition by name.
pub fn native_tool(name: &str) -> Option<Tool> {
    NATIVE_TOOLS
        .iter()
        .find(|tool| tool.name.as_ref() == name)
        .cloned()
}

/// Tools in a category, sorted by name.
pub fn tools_in_category(category: ToolCategory) -> impl Iterator<Item = &'static str> {
    native_tool_names().filter(move |name| category_of(name) == Some(category))
}

/// The `#[tool(description = ...)]` text, which is also what `tools/list`
/// advertises.
pub fn description_of(name: &str) -> Option<String> {
    NATIVE_TOOLS
        .iter()
        .find(|tool| tool.name.as_ref() == name)
        .and_then(|tool| tool.description.as_ref())
        .map(|description| description.to_string())
}

/// First sentence of a tool's description, for compact catalog listings.
pub fn short_description_of(name: &str) -> Option<String> {
    description_of(name).map(|description| {
        let compact = description.split_whitespace().collect::<Vec<_>>().join(" ");
        match compact.split_once(". ") {
            Some((first, _)) => format!("{first}."),
            None => compact,
        }
    })
}

/// Rank tools against a free-text query. Names weigh more than descriptions,
/// which weigh more than the category name. Returns names best-first.
pub fn search(query: &str, limit: usize) -> Vec<&'static str> {
    let words = query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_string)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words.is_empty() {
        return Vec::new();
    }

    let mut scored = native_tool_names()
        .filter_map(|name| {
            let name_lower = name.to_lowercase();
            let description = description_of(name).unwrap_or_default().to_lowercase();
            let category = category_of(name).map(ToolCategory::as_str).unwrap_or("");
            let mut score = 0usize;
            for word in &words {
                if name_lower.contains(word.as_str()) {
                    score += 10;
                }
                if description.contains(word.as_str()) {
                    score += 5;
                }
                if category.contains(word.as_str()) {
                    score += 2;
                }
            }
            (score > 0).then_some((name, score))
        })
        .collect::<Vec<_>>();

    // Stable within a score: `native_tool_names` is already sorted.
    scored.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
    scored
        .into_iter()
        .take(limit)
        .map(|(name, _)| name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_catalog_is_derived_from_the_tool_router() {
        let names = native_tool_names().collect::<Vec<_>>();

        assert_eq!(names.len(), IdaMcpServer::tool_router().map.len());
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        for expected in ["open_idb", "decompile", "find_paths", "sdk_mutation"] {
            assert!(names.contains(&expected), "missing native tool {expected}");
        }
    }

    #[test]
    fn every_native_tool_has_a_category() {
        let uncategorized = native_tool_names()
            .filter(|name| category_of(name).is_none())
            .collect::<Vec<_>>();

        assert!(
            uncategorized.is_empty(),
            "add these tools to catalog::category_of: {uncategorized:?}"
        );
    }

    #[test]
    fn every_category_has_at_least_one_tool() {
        for category in ToolCategory::all() {
            assert!(
                tools_in_category(*category).next().is_some(),
                "category {} has no tools",
                category.as_str()
            );
        }
    }

    #[test]
    fn search_ranks_name_matches_first() {
        // A name hit outweighs a description hit: `callers` is *named* for the
        // query, several other tools merely mention callers in their prose.
        let results = search("callers", 5);

        assert!(results.len() > 1, "other tools describe callers too");
        assert_eq!(results.first(), Some(&"callers"));
    }

    /// An intent query has to surface both the primitive that answers exactly
    /// it and the composite that answers it as part of a bigger picture.
    ///
    /// Composite tools name and describe a lot of ground on purpose, which is
    /// also what makes them score high on a naive substring search — so this
    /// asserts co-presence rather than a fixed order. Pinning first place here
    /// would only encode which description happens to be longer today.
    #[test]
    fn search_surfaces_composite_and_primitive_together() {
        let results = search("find callers of a function", 5);

        assert!(results.contains(&"callers"), "{results:?}");
        assert!(results.contains(&"analyze_function"), "{results:?}");
    }

    #[test]
    fn short_description_keeps_the_first_sentence() {
        let full = description_of("tool_catalog").expect("tool_catalog description");
        let short = short_description_of("tool_catalog").expect("tool_catalog description");

        assert!(full.len() > short.len(), "multi-sentence description");
        assert!(short.ends_with('.'));
        assert!(!short.contains(". "));
        // Single-sentence descriptions are passed through untouched.
        assert_eq!(
            short_description_of("decompile"),
            description_of("decompile")
        );
    }

    #[test]
    fn native_tools_carry_annotations_and_clean_schemas() {
        for tool in native_tools() {
            assert!(
                tool.annotations.is_some(),
                "tool {} has no annotations",
                tool.name
            );
            assert!(
                !tool.input_schema.contains_key("$schema"),
                "tool {} leaked $schema",
                tool.name
            );
        }
    }
}
