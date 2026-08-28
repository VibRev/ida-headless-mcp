//! The agent skills this binary carries.
//!
//! `skills/idapython` is 105 files of IDAPython reference — knowledge a model
//! needs in order to use the tool surface well, and that no tool signature can
//! convey. The engine ships as one executable, so `build.rs` compresses the
//! tree into the binary and `skills export` writes it back out.
//!
//! Everything below the surface of this file is [`vibrev_skills`]: the archive
//! format, the frontmatter validation, the fingerprint, the traversal guard and
//! the two verbs. What stays here is the content and the name it answers to.
//!
//! Nothing here touches idalib. `skills list` and `skills export` are
//! answerable with no database, no license and no IDA installation, which is
//! what lets an installer ask a binary what it offers before deciding anything.

/// Every skill compiled into this binary.
pub static SKILLS: vibrev_skills::Embedded = vibrev_skills::embedded!();

#[cfg(test)]
mod tests {
    use super::SKILLS;

    /// `vibrev-skills` proves that packing and unpacking agree. What it cannot
    /// prove is that *this* repository's `skills/` reached the binary — a
    /// build.rs that silently walked the wrong directory would pass every test
    /// over there and ship an empty engine.
    #[test]
    fn the_binary_ships_the_repository_skills() {
        let idapython = SKILLS
            .by_name("idapython")
            .expect("idapython is vendored in this repository");
        assert!(idapython.files > 1, "SKILL.md alone is not the whole skill");
        assert!(idapython.description.contains("IDA"));
        assert_eq!(idapython.fingerprint.len(), 16);
    }

    /// An export has to reproduce the repository byte for byte, because that is
    /// the whole claim: what a user gets in `~/.claude/skills` is what is
    /// committed here.
    #[test]
    fn export_reproduces_the_source_tree_byte_for_byte() {
        let dir = std::env::temp_dir().join(format!("ida-mcp-skills-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let exported = SKILLS.export(&dir, None).expect("export succeeds");
        assert_eq!(exported.len(), SKILLS.all().len());

        // `skills/` sits next to the manifest for the root build and two levels
        // up for the per-SDK ones — the same shape `build.rs::source_root` walks.
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = [manifest.join("skills"), manifest.join("../../skills")]
            .into_iter()
            .find(|p| p.is_dir())
            .expect("the repository still has a skills/ directory");

        for item in &exported {
            for written in &item.files {
                let rel = written
                    .strip_prefix(&dir)
                    .expect("every written file is under the export directory");
                assert_eq!(
                    std::fs::read(written).expect("written file is readable"),
                    std::fs::read(source.join(rel)).expect("source file is readable"),
                    "{} differs from the repository copy",
                    rel.display()
                );
            }
        }
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
