//! What this engine tells `vibrev-kit::policy` about itself, for the native
//! (worker) tool surface.
//!
//! The mechanism — how `--toolsets`, `--tools`, `--exclude-tools` and
//! `--read-only` compose, in what order, what an empty result means, and how
//! `--read-only` derives its deny list from each tool's `readOnlyHint` — lives
//! in the kit, shared with `bn-headless-mcp`. What lives here is what is
//! genuinely about IDA: the twelve categories, the names a user may type
//! instead of them, and the four tools that must survive every narrowing.
//!
//! The `--unsafe` gate is *not* part of this. It is a second, independent door
//! that only the supervisor has (see [`is_unsafe_tool`](crate::supervisor::server::is_unsafe_tool)),
//! and the kit deliberately has no notion of hiding a tool the engine chose to
//! publish.

use vibrev_kit::policy::{PolicyArgs, PolicyError, Taxonomy, ToolPolicy};

use crate::server::catalog::{self, ToolCategory};

/// Tools that survive every narrowing except an explicit exclusion.
///
/// These write — `open_idb` leases a worker, `load_debug_info` mutates the
/// database — but a server without them cannot open anything, so every other
/// tool it advertises answers "no database open". That happens by two unrelated
/// routes and this covers both: `--read-only` drops them for being writers, and
/// `--toolsets disassembly` drops them for not being disassembly.
///
/// Naming one in `--exclude-tools` still removes it. Picking a category is a
/// guess about what you need; naming a tool is a statement.
pub const READ_ONLY_LIFECYCLE: &[&str] = &["open_idb", "close_idb", "open_dsc", "load_debug_info"];

/// Spellings a user may type for a category, beyond the canonical name.
///
/// Case and `-`/space folding is the kit's job; these are the ones that need
/// actual knowledge of what this engine calls things.
const CATEGORY_ALIASES: &[(&str, &str)] = &[
    ("function", "functions"),
    ("disasm", "disassembly"),
    ("decompiler", "decompile"),
    ("xref", "xrefs"),
    ("references", "xrefs"),
    ("controlflow", "control_flow"),
    ("cfg", "control_flow"),
    ("data", "memory"),
    ("meta", "metadata"),
    ("info", "metadata"),
    ("type", "types"),
    ("structs", "types"),
    ("edit", "editing"),
    ("script", "scripting"),
    ("python", "scripting"),
];

/// The twelve categories, as the kit's taxonomy.
///
/// Built from `catalog::tools_in_category` rather than restated, so a tool that
/// moves category here moves in the filter without anyone editing this file.
pub fn native_taxonomy() -> Taxonomy {
    let mut taxonomy = Taxonomy::new();
    for category in ToolCategory::all() {
        for name in catalog::tools_in_category(*category) {
            taxonomy.assign(name, category.as_str());
        }
    }
    for (spelling, canonical) in CATEGORY_ALIASES {
        taxonomy.alias(spelling, canonical);
    }
    taxonomy
}

/// The native surface's policy, from CLI/env input.
pub fn native_policy(args: &PolicyArgs) -> Result<ToolPolicy, PolicyError> {
    args.apply(
        ToolPolicy::builder(&catalog::native_tools())
            .taxonomy(native_taxonomy())
            .essential(READ_ONLY_LIFECYCLE),
    )
    .build()
}

/// Native tools `--read-only` removes.
///
/// Derived from the policy rather than computed alongside it, so this can only
/// ever report what `--read-only` really does. Kept as a public function because
/// `tool_catalog` and the surface tests want to name the set.
pub fn read_only_deny_list() -> Vec<&'static str> {
    let policy = native_policy(&PolicyArgs {
        read_only: true,
        ..PolicyArgs::default()
    })
    .expect("a read-only native surface always keeps its readers");
    catalog::native_tool_names()
        .filter(|name| !policy.allows(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::catalog;

    fn cat(s: &str) -> Vec<String> {
        vec![s.to_string()]
    }

    fn policy(
        toolsets: &[String],
        tools: &[String],
        exclude: &[String],
        read_only: bool,
    ) -> ToolPolicy {
        native_policy(&PolicyArgs {
            toolsets: toolsets.to_vec(),
            tools: tools.to_vec(),
            exclude_tools: exclude.to_vec(),
            read_only,
        })
        .expect("policy")
    }

    #[test]
    fn no_inputs_enables_everything_and_is_inactive() {
        let f = policy(&[], &[], &[], false);
        assert!(!f.is_active());
        assert!(f.allows("open_idb"));
        assert!(f.allows("decompile"));
        assert!(f.allows("run_script"));
        assert!(f.allows("patch"));
        assert_eq!(
            f.advertise(catalog::native_tools()).len(),
            catalog::native_tool_names().count()
        );
    }

    /// Naming a category narrows to it — but not so far that the result cannot
    /// open a database.
    ///
    /// Dropping `open_idb` because "core is not selected" would be a faithful
    /// reading of the category list and still wrong: `ida worker --toolsets
    /// disassembly` would come up with a disassembly surface and no way to load
    /// anything into it, so every tool it advertised would answer "no database
    /// open". `bn-headless-mcp` reaches the same dead end from `--toolsets
    /// patch`, which is why the lifecycle exemption lives in one place rather
    /// than two.
    #[test]
    fn toolsets_replace_implicit_default_all() {
        let f = policy(&cat("disassembly,decompile"), &[], &[], false);
        assert!(f.is_active());
        assert!(f.allows("decompile"));
        assert!(f.allows("disasm"));
        // Categories not selected still do not leak in.
        assert!(!f.allows("run_script"));
        assert!(!f.allows("patch"));
        // …except the lifecycle, without which none of the above is reachable.
        for name in READ_ONLY_LIFECYCLE {
            assert!(f.allows(name), "{name} must stay reachable");
        }
    }

    /// And an operator who really means "no lifecycle" says so by name.
    #[test]
    fn an_explicit_exclusion_still_reaches_the_lifecycle() {
        let f = policy(&cat("disassembly"), &[], &cat("open_idb"), false);
        assert!(!f.allows("open_idb"));
        assert!(f.allows("close_idb"));
        assert!(f.allows("disasm"));
    }

    #[test]
    fn tools_add_to_explicit_toolsets() {
        let f = policy(&cat("decompile"), &cat("open_idb,callees"), &[], false);
        assert!(f.allows("decompile")); // from toolset
        assert!(f.allows("open_idb")); // from explicit tool
        assert!(f.allows("callees")); // from explicit tool
        assert!(!f.allows("run_script"));
    }

    #[test]
    fn lumina_tools_follow_read_and_write_categories() {
        let metadata = policy(&cat("metadata"), &[], &[], false);
        assert!(metadata.allows("lumina_lookup"));
        assert!(!metadata.allows("lumina_apply"));

        let editing = policy(&cat("editing"), &[], &[], false);
        assert!(editing.allows("lumina_apply"));
        assert!(!editing.allows("lumina_lookup"));
    }

    /// The aliases a user may type, plus the folding the kit adds on top.
    #[test]
    fn a_category_is_recognised_by_its_alias_and_however_it_was_cased() {
        for spelling in ["scripting", "script", "python", "PYTHON", "Script"] {
            let f = policy(&cat(spelling), &[], &[], false);
            assert!(f.allows("run_script"), "{spelling} should reach scripting");
        }
        for spelling in ["control_flow", "controlflow", "cfg", "Control-Flow"] {
            let f = policy(&cat(spelling), &[], &[], false);
            assert!(
                f.allows("callgraph"),
                "{spelling} should reach control_flow"
            );
        }
    }

    #[test]
    fn exclude_tools_wins_over_includes() {
        let f = policy(&cat("core"), &cat("run_script"), &cat("run_script"), false);
        // open_idb (core) stays; run_script was added then excluded.
        assert!(f.allows("open_idb"));
        assert!(!f.allows("run_script"));
    }

    #[test]
    fn read_only_strips_mutating_tools() {
        let f = policy(&[], &[], &[], true);
        let denied = read_only_deny_list();
        assert!(denied.contains(&"sdk_mutation"));
        assert!(denied.contains(&"analyze_funcs"));
        assert!(denied.contains(&"bookmark_add"));
        assert!(denied.contains(&"comment_append"));
        assert!(
            !denied.contains(&"infer_types"),
            "infer_types only guesses; it does not write"
        );
        for name in &denied {
            assert!(!f.allows(name), "read-only must drop {name}");
        }
        for name in READ_ONLY_LIFECYCLE {
            assert!(f.allows(name), "read-only must keep lifecycle {name}");
        }
        for name in [
            "analysis_status",
            "task_status",
            "recent_operations",
            "tool_catalog",
            "tool_help",
            "idb_meta",
            "lumina_lookup",
            "infer_types",
            "decompile",
        ] {
            assert!(f.allows(name), "read-only must keep {name}");
        }
    }

    /// The deny list is a consequence of `readOnlyHint`, not a list anyone keeps.
    #[test]
    fn deny_list_is_exactly_the_non_lifecycle_writers() {
        let denied = read_only_deny_list();
        for tool in catalog::native_tools() {
            let name = tool.name.to_string();
            let annotated_read_only = tool
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint)
                == Some(true);
            let kept = READ_ONLY_LIFECYCLE.contains(&name.as_str());
            assert_eq!(
                denied.contains(&name.as_str()),
                !annotated_read_only && !kept,
                "{name}: deny list must follow readOnlyHint and the lifecycle list"
            );
        }
    }

    #[test]
    fn unknown_toolset_rejected() {
        let error = native_policy(&PolicyArgs {
            toolsets: cat("not_a_category"),
            ..PolicyArgs::default()
        })
        .unwrap_err();
        let PolicyError::UnknownCategory { name, known } = &error else {
            panic!("wrong error: {error}");
        };
        assert_eq!(name, "not_a_category");
        assert!(known.contains(&"decompile".to_string()));
    }

    #[test]
    fn unknown_tool_rejected() {
        assert_eq!(
            native_policy(&PolicyArgs {
                tools: cat("not_a_tool"),
                ..PolicyArgs::default()
            })
            .unwrap_err(),
            PolicyError::UnknownTool("not_a_tool".to_string())
        );
    }

    /// A selection that leaves only the lifecycle is empty in the sense that
    /// matters: the server can open a database and then do nothing with it.
    #[test]
    fn empty_final_set_rejected() {
        assert_eq!(
            native_policy(&PolicyArgs {
                tools: cat("decompile"),
                exclude_tools: cat("decompile"),
                ..PolicyArgs::default()
            })
            .unwrap_err(),
            PolicyError::Empty
        );
    }

    #[test]
    fn comma_separated_inputs_split_correctly() {
        let commas = policy(&cat("disassembly, decompile"), &[], &[], false);
        let repeats = policy(
            &["disassembly".to_string(), "decompile".to_string()],
            &[],
            &[],
            false,
        );
        for name in ["disasm", "decompile", "open_idb"] {
            assert!(commas.allows(name));
            assert!(repeats.allows(name));
        }
        assert!(!commas.allows("run_script"));
    }
}
