//! Leftover unpacked IDA database parts left next to an input after a failed open.
//!
//! A timed-out or killed `open` can write `.id0`/`.id1`/`.id2`/`.nam`/`.til`
//! beside the input. The next open of the same path then fails with
//! "database is corrupted beyond repair". Packed `.i64`/`.idb` files and any
//! unpacked parts that already existed before this attempt are kept.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const UNPACKED_EXTENSIONS: &[&str] = &["id0", "id1", "id2", "nam", "til"];

fn has_ida_database_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "i64" | "idb" | "id0"))
}

fn packed_database_for_input(input: &Path) -> PathBuf {
    if has_ida_database_extension(input) {
        return input.to_path_buf();
    }
    let mut packed = OsString::from(input.as_os_str());
    packed.push(".i64");
    PathBuf::from(packed)
}

/// Candidate leftover unpacked parts for `input`.
///
/// Covers IDA's real unpack (`set_extension` on the packed `.i64`/`.idb`,
/// generating that path first when `input` is raw) and the append form used by
/// ida-pro-mcp / the test justfile (`input` + `.id0`).
pub(crate) fn leftover_unpacked_parts(input: &Path) -> Vec<PathBuf> {
    let packed = packed_database_for_input(input);
    let mut parts = Vec::new();
    let mut seen = HashSet::new();

    for ext in UNPACKED_EXTENSIONS {
        let mut path = packed.clone();
        path.set_extension(ext);
        if seen.insert(path.clone()) {
            parts.push(path);
        }
    }

    for ext in UNPACKED_EXTENSIONS {
        let mut os = OsString::from(input.as_os_str());
        os.push(".");
        os.push(ext);
        let path = PathBuf::from(os);
        if seen.insert(path.clone()) {
            parts.push(path);
        }
    }

    parts
}

pub(crate) fn existing_leftover_parts(input: &Path) -> HashSet<PathBuf> {
    leftover_unpacked_parts(input)
        .into_iter()
        .filter(|path| path.exists())
        .collect()
}

/// Delete leftover unpacked parts that were not in `preserve`.
///
/// Never deletes packed `.i64`/`.idb`. `NotFound` is ignored; other errors are
/// logged and otherwise swallowed.
pub(crate) fn cleanup_leftover_parts(input: &Path, preserve: &HashSet<PathBuf>) {
    for path in leftover_unpacked_parts(input) {
        if preserve.contains(&path) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    "removed leftover unpacked IDA database part"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(
                    path = %path.display(),
                    error = %error,
                    "failed to remove leftover unpacked IDA database part"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_leftover_parts, existing_leftover_parts, leftover_unpacked_parts,
        UNPACKED_EXTENSIONS,
    };
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn part_set(input: &str) -> BTreeSet<PathBuf> {
        leftover_unpacked_parts(Path::new(input))
            .into_iter()
            .collect()
    }

    fn expected_set_extension(packed: &str) -> BTreeSet<PathBuf> {
        UNPACKED_EXTENSIONS
            .iter()
            .map(|ext| {
                let mut path = PathBuf::from(packed);
                path.set_extension(ext);
                path
            })
            .collect()
    }

    fn expected_append(input: &str) -> BTreeSet<PathBuf> {
        UNPACKED_EXTENSIONS
            .iter()
            .map(|ext| PathBuf::from(format!("{input}.{ext}")))
            .collect()
    }

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ida-mcp-leftover-{unique}"));
        fs::create_dir(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn leftover_candidates_for_extensionless_raw_input() {
        let parts = part_set("/tmp/foo");
        let expected = expected_set_extension("/tmp/foo.i64");
        assert_eq!(parts, expected);
        assert_eq!(parts, expected_append("/tmp/foo"));
        assert!(!parts.iter().any(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| {
                    ext.eq_ignore_ascii_case("i64") || ext.eq_ignore_ascii_case("idb")
                })
        }));
    }

    #[test]
    fn leftover_candidates_for_packed_i64() {
        let parts = part_set("/tmp/foo.i64");
        let mut expected = expected_set_extension("/tmp/foo.i64");
        expected.extend(expected_append("/tmp/foo.i64"));
        assert_eq!(parts, expected);
        assert!(parts.contains(Path::new("/tmp/foo.id0")));
        assert!(parts.contains(Path::new("/tmp/foo.i64.id0")));
        assert!(!parts.contains(Path::new("/tmp/foo.i64")));
    }

    #[test]
    fn leftover_candidates_for_raw_elf() {
        let parts = part_set("/tmp/foo.elf");
        let expected = expected_set_extension("/tmp/foo.elf.i64");
        assert_eq!(parts, expected);
        assert_eq!(parts, expected_append("/tmp/foo.elf"));
        assert!(parts.contains(Path::new("/tmp/foo.elf.id0")));
        assert!(!parts.contains(Path::new("/tmp/foo.elf.i64")));
        assert!(!parts.contains(Path::new("/tmp/foo.id0")));
    }

    #[test]
    fn cleanup_preserves_preexisting_parts_and_packed_databases() {
        let dir = unique_temp_dir();
        let input = dir.join("foo.i64");
        let preexisting = dir.join("foo.id0");
        let created = dir.join("foo.id1");
        fs::write(&input, b"packed").expect("write packed database");
        fs::write(&preexisting, b"old").expect("write preexisting id0");

        let preserve = existing_leftover_parts(&input);
        assert!(preserve.contains(&preexisting));
        assert!(!preserve.contains(&created));

        fs::write(&created, b"new").expect("write leftover id1");
        cleanup_leftover_parts(&input, &preserve);

        assert!(input.exists(), "packed .i64 must be left alone");
        assert!(
            preexisting.exists(),
            "parts that existed before open must be kept"
        );
        assert!(
            !created.exists(),
            "parts written by this open must be removed"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
