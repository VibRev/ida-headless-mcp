//! What the supervisor's public surface tells `vibrev-kit::policy` about itself.
//!
//! Same split as the native side: the composition order, the read-only
//! derivation and the CLI flags are the kit's; the taxonomy and the lifecycle
//! list are this engine's. The two faces differ in three ways and nothing else:
//!
//! * a different catalog — worker-local database lifecycle is replaced by the
//!   supervisor's own `idb_*` session tools;
//! * those session tools stand in for `open_idb` / `close_idb`, so they inherit
//!   [`ToolCategory::Core`] and answer to the worker-local names as aliases;
//! * they are the essential set, because a supervisor that cannot open a
//!   database advertises tools that can only answer "no database open".
//!
//! The `--unsafe` gate stays out of the policy on purpose. It is a second,
//! independent door — see [`is_unsafe_tool`](super::server::is_unsafe_tool) —
//! and `vibrev-kit` has no notion of hiding a tool the engine chose to publish.

use vibrev_kit::policy::{PolicyArgs, PolicyError, Taxonomy, ToolPolicy};

use crate::server::catalog::ToolCategory;
use crate::server::tool_filter::{native_taxonomy, read_only_deny_list};
use crate::supervisor::server::{SupervisorServer, SESSION_TOOLS};

/// Tools that can change IDA state or write a database, as `--read-only` sees
/// them. Session lifecycle is not among them: a read-only supervisor still
/// opens, enumerates and releases databases.
pub fn read_only_deny_list_names() -> Vec<&'static str> {
    read_only_deny_list()
}

/// The public surface's taxonomy.
pub fn supervisor_taxonomy() -> Taxonomy {
    let mut taxonomy = native_taxonomy();
    for name in SESSION_TOOLS {
        taxonomy.assign(name, ToolCategory::Core.as_str());
    }
    // Worker-local lifecycle names map onto the session tools so that existing
    // `--tools=open_idb,...` configurations keep working.
    taxonomy.alias("open_idb", "idb_open");
    taxonomy.alias("open_dsc", "idb_open");
    taxonomy.alias("close_idb", "idb_close");
    taxonomy
}

/// The public surface's policy, from CLI/env input.
///
/// Built against the unfiltered catalog — the same list `tools/list` would show
/// with nothing selected — so that a name is legal here exactly when a client
/// could have seen it.
pub fn supervisor_policy(args: &PolicyArgs) -> Result<ToolPolicy, PolicyError> {
    let catalog = SupervisorServer::unfiltered_catalog();
    args.apply(
        ToolPolicy::builder(&catalog)
            .taxonomy(supervisor_taxonomy())
            .essential(SESSION_TOOLS),
    )
    .build()
}

/// Refuse to start when the unsafe gate would leave nothing advertised.
///
/// The gate is not part of the policy — `vibrev-kit` has no notion of hiding a
/// tool the engine published — so the interaction between the two doors is this
/// engine's to check. `--tools=run_script` without `--unsafe` is a server that
/// comes up looking configured and answers `tools/list` with nothing.
pub fn validate_unsafe_gate(policy: &ToolPolicy, unsafe_enabled: bool) -> Result<(), String> {
    if unsafe_enabled {
        return Ok(());
    }
    // Session tools do not count, for the same reason `PolicyError::Empty`
    // does not count them: they are what lets *other* tools be used, so a
    // catalog of nothing but lifecycle can open a database and then do nothing
    // with it.
    let survives = SupervisorServer::unfiltered_catalog()
        .into_iter()
        .any(|tool| {
            let name = tool.name.as_ref();
            policy.allows(name)
                && !crate::supervisor::server::is_unsafe_tool(name)
                && !SESSION_TOOLS.contains(&name)
        });
    if survives {
        Ok(())
    } else {
        Err("every selected tool is behind --unsafe; pass it or widen the selection".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::server::public_tool_names;

    fn policy(toolsets: &[&str], tools: &[&str], exclude: &[&str], read_only: bool) -> ToolPolicy {
        supervisor_policy(&PolicyArgs {
            toolsets: toolsets.iter().map(|s| s.to_string()).collect(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
            exclude_tools: exclude.iter().map(|s| s.to_string()).collect(),
            read_only,
        })
        .expect("policy")
    }

    /// Every advertised name has a category, or `--toolsets` could never reach
    /// it and the only way in would be to name it.
    #[test]
    fn every_public_tool_has_a_category() {
        let taxonomy = supervisor_taxonomy();
        let categorised: std::collections::BTreeSet<&str> = taxonomy
            .categories()
            .into_iter()
            .filter_map(|category| taxonomy.members_of(category))
            .flatten()
            .map(String::as_str)
            .collect();
        for name in public_tool_names() {
            assert!(categorised.contains(name), "{name} has no category");
        }
    }

    #[test]
    fn toolsets_filter_native_names() {
        let f = policy(&["decompile"], &[], &[], false);
        assert!(f.allows("decompile"));
        assert!(!f.allows("run_script"));
    }

    /// The lifecycle survives a category that does not contain it, because a
    /// supervisor that cannot open a database cannot do anything else either.
    #[test]
    fn narrowing_to_a_category_keeps_the_session_tools() {
        let f = policy(&["decompile"], &[], &[], false);
        for name in SESSION_TOOLS {
            assert!(f.allows(name), "{name} must stay reachable");
        }
    }

    #[test]
    fn read_only_strips_mutations_and_keeps_lifecycle() {
        let f = policy(&[], &[], &[], true);
        for name in read_only_deny_list_names() {
            assert!(!f.allows(name), "read-only leaked {name}");
        }
        for name in SESSION_TOOLS {
            assert!(f.allows(name), "read-only removed {name}");
        }
    }

    #[test]
    fn read_only_keeps_server_health() {
        assert!(policy(&[], &[], &[], true).allows("server_health"));
    }

    /// Worker-local names still resolve, so a config written before the
    /// supervisor existed keeps working.
    ///
    /// Paired with a real tool in both cases: a selection of nothing but
    /// lifecycle is `PolicyError::Empty`, which is its own (correct) behaviour
    /// and not what this test is about.
    #[test]
    fn explicit_tools_and_lifecycle_aliases_compose() {
        let f = policy(&[], &["open_idb", "decompile"], &[], false);
        assert!(f.allows("idb_open"), "open_idb must resolve to idb_open");
        assert!(f.allows("decompile"));

        let closing = policy(&[], &["close_idb", "decompile"], &[], false);
        assert!(closing.allows("idb_close"), "close_idb -> idb_close");
    }

    /// …and a selection that is *only* lifecycle is empty in the sense that
    /// matters.
    #[test]
    fn a_selection_of_nothing_but_lifecycle_is_empty() {
        assert_eq!(
            supervisor_policy(&PolicyArgs {
                tools: vec!["close_idb".to_string()],
                ..PolicyArgs::default()
            })
            .unwrap_err(),
            PolicyError::Empty
        );
    }

    #[test]
    fn unknown_names_and_empty_results_are_rejected() {
        assert_eq!(
            supervisor_policy(&PolicyArgs {
                tools: vec!["not_a_tool".to_string()],
                ..PolicyArgs::default()
            })
            .unwrap_err(),
            PolicyError::UnknownTool("not_a_tool".to_string())
        );
        assert_eq!(
            supervisor_policy(&PolicyArgs {
                tools: vec!["decompile".to_string()],
                exclude_tools: vec!["decompile".to_string()],
                ..PolicyArgs::default()
            })
            .unwrap_err(),
            PolicyError::Empty
        );
    }

    #[test]
    fn the_unsafe_gate_cannot_leave_an_empty_catalog() {
        let only_unsafe = policy(&[], &["run_script"], &[], false);
        assert!(validate_unsafe_gate(&only_unsafe, false).is_err());
        assert!(validate_unsafe_gate(&only_unsafe, true).is_ok());

        let wider = policy(&[], &["run_script", "decompile"], &[], false);
        assert!(validate_unsafe_gate(&wider, false).is_ok());
    }

    /// Worker-local database lifecycle is not on this face at all, so naming it
    /// as a category member must not conjure it back.
    #[test]
    fn worker_local_lifecycle_never_reaches_the_public_face() {
        let f = policy(&["core"], &[], &[], false);
        for name in ["open_idb", "close_idb", "open_dsc"] {
            assert!(
                !f.allows(name),
                "{name} is worker-local; the supervisor owns idb_open/idb_close"
            );
        }
        assert!(f.allows("idb_open"));
    }
}
