//! Whether this process's two halves of IDA came from the same install.
//!
//! IDA is resolved by two different mechanisms that nobody reconciles:
//!
//! - the **core library** (`libida.so` / `libida.dylib` / `ida.dll`) comes from
//!   the dynamic linker, which honours the RUNPATH `build.rs` embeds — and that
//!   RUNPATH deliberately names *several* IDA installs, not one;
//! - the **resource tree** (`plugins/`, `procs/`, `loaders/`, `cfg/`) comes from
//!   IDA itself, which honours `$IDADIR`.
//!
//! Point `$IDADIR` at 9.3 on a machine that also has 9.4 and both halves resolve
//! happily, to different releases. No version check fires, because there is no
//! version mismatch to find: `idalib::SDK_VERSION` and `idalib::version()` both
//! say 9.4, and they are both right — the core library really is 9.4. What
//! breaks is everything IDA loads out of `$IDADIR` afterwards: 9.3's `hexarc.so`
//! will not initialize into a 9.4 core ("Hex-Rays decompiler is not available"),
//! 9.3's processor modules fault inside it (SIGSEGV, which the supervisor
//! reports as "worker transport closed"), and 9.3's `dscu.so` cannot open a
//! shared cache. Three unrelated-looking failures, none naming the cause.
//!
//! So this module does not compare version numbers. It asks the question the
//! version check cannot: did the two halves come from the same directory?

use std::path::{Path, PathBuf};

use tracing::{debug, warn};

/// Environment variable IDA reads to locate its resource tree.
const IDADIR_ENV: &str = "IDADIR";

/// The flag that turns a refusal into a warning.
pub const ALLOW_MISMATCH_FLAG: &str = "--allow-ida-mismatch";
/// Its environment spelling, which is also how a child worker inherits it.
pub const ALLOW_MISMATCH_ENV: &str = "IDA_MCP_ALLOW_IDA_MISMATCH";

/// How the resource directory was discovered.
///
/// The two sources answer at different times and catch different mistakes.
/// `$IDADIR` is readable before IDA exists, which is what makes the startup gate
/// possible at all; `idadir()` is IDA's own answer and also covers the installs
/// it resolves some other way (`$IDAUSR`, the registry, the working directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDirSource {
    /// `$IDADIR`, read before IDA is initialized.
    Environment,
    /// `idadir(nullptr)`, asked of IDA once it is.
    Ida,
}

impl ResourceDirSource {
    fn describe(self) -> &'static str {
        match self {
            Self::Environment => "$IDADIR",
            Self::Ida => "IDA's own idadir()",
        }
    }
}

/// Two halves of IDA that did not come from the same install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallMismatch {
    /// Directory holding the core library the dynamic linker actually loaded.
    pub core_dir: PathBuf,
    /// Directory IDA will load plugins, processor modules and loaders from.
    pub resource_dir: PathBuf,
    pub source: ResourceDirSource,
}

/// Says what is wrong, in which two directories, and what to do about it.
///
/// Long for an error message on purpose. The failures this replaces
/// (`Decompiler not available`, a bare SIGSEGV, a DSC that will not open) are
/// each short, plausible and pointed at the wrong thing, so a reader who has
/// been chasing one of them needs to be told that they were chasing a symptom.
impl std::fmt::Display for InstallMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IDA installation mismatch: this process loaded IDA's core library from\n  \
             {core}\n\
             but IDA loads its plugins, processor modules and loaders from\n  \
             {resources}\n\
             (resolved from {source}).\n\
             \n\
             Both halves have to come from one install. A mixed one does not fail \
             cleanly — it reports \"Hex-Rays decompiler is not available\", faults \
             inside a processor module, or refuses to open a dyld_shared_cache, and \
             none of those name the real cause.\n\
             \n\
             Fix one of:\n  \
             - point {env} at {core};\n  \
             - use the ida-headless-mcp build made for the IDA in {resources};\n  \
             - pass {flag} ({env_allow}=1) to continue anyway.",
            core = self.core_dir.display(),
            resources = self.resource_dir.display(),
            source = self.source.describe(),
            env = IDADIR_ENV,
            flag = ALLOW_MISMATCH_FLAG,
            env_allow = ALLOW_MISMATCH_ENV,
        )
    }
}

impl std::error::Error for InstallMismatch {}

/// Outcome of comparing the two halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallCheck {
    /// Both halves resolved to the same directory — or nothing overrode the
    /// resource tree, in which case IDA derives it from the core library and
    /// they agree by construction.
    Consistent,
    /// One half could not be identified. Not a finding: a stub build has no IDA
    /// core to locate, and refusing to start over an unanswerable question would
    /// be worse than the mismatch this module exists to catch.
    Undetermined(&'static str),
    Mixed(InstallMismatch),
}

/// Refuse to run on a mixed install, before anything has a chance to fail
/// misleadingly.
///
/// Reads only `$IDADIR` and the dynamic linker's list of loaded objects, so it
/// costs nothing and — the point of the exercise — needs no initialized IDA.
/// Both other call sites would report far too late: `serve` never initializes
/// IDA in its own process at all, and a `worker` defers initialization to its
/// first tool call.
pub fn preflight(allow_mismatch: bool) -> Result<(), InstallMismatch> {
    let resource_dir = std::env::var_os(IDADIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    report(
        decide(
            loaded_core_dir().map(|dir| normalize(&dir)),
            resource_dir.map(|dir| normalize(&dir)),
            ResourceDirSource::Environment,
        ),
        allow_mismatch,
    )
}

/// The same question asked again once IDA can answer it itself.
///
/// Catches the installs `$IDADIR` does not describe — resolved through
/// `$IDAUSR`, the Windows registry, or the working directory.
pub fn check_initialized(allow_mismatch: bool) -> Result<(), InstallMismatch> {
    let core_dir = loaded_core_dir().map(|dir| normalize(&dir));
    let resource_dir = crate::ida::sdk_bridge::idadir().map(|dir| normalize(&dir));
    // Logged unconditionally, and at info: "which IDA is this actually running
    // against" is the first thing anyone reading a failed session's log wants,
    // and it is not answerable from anywhere else.
    tracing::info!(
        core_dir = ?core_dir,
        resource_dir = ?resource_dir,
        "Resolved IDA installation"
    );
    report(
        decide(core_dir, resource_dir, ResourceDirSource::Ida),
        allow_mismatch,
    )
}

/// The mismatch this process is running under, if it was waived into one.
///
/// Asked by anything that has to explain a *downstream* failure — a decompiler
/// that will not initialize, a loader that will not open a cache — because a
/// mixed installation is the explanation for all of them and saying so beats
/// letting the caller rediscover it.
pub fn current_mismatch() -> Option<InstallMismatch> {
    match decide(
        loaded_core_dir().map(|dir| normalize(&dir)),
        crate::ida::sdk_bridge::idadir().map(|dir| normalize(&dir)),
        ResourceDirSource::Ida,
    ) {
        InstallCheck::Mixed(mismatch) => Some(mismatch),
        InstallCheck::Consistent | InstallCheck::Undetermined(_) => None,
    }
}

/// Log the outcome, and turn a mismatch into a refusal unless waived.
fn report(check: InstallCheck, allow_mismatch: bool) -> Result<(), InstallMismatch> {
    match check {
        InstallCheck::Consistent => Ok(()),
        InstallCheck::Undetermined(reason) => {
            debug!(reason, "Skipping the IDA install consistency check");
            Ok(())
        }
        InstallCheck::Mixed(mismatch) if allow_mismatch => {
            // Still logged in full: the caller waived the refusal, not the
            // diagnosis, and the failures downstream will need it.
            warn!("{mismatch}\n\nContinuing because {ALLOW_MISMATCH_FLAG} was given.");
            Ok(())
        }
        InstallCheck::Mixed(mismatch) => Err(mismatch),
    }
}

/// The decision itself, with the filesystem already consulted.
///
/// Separated from [`preflight`] so the outcome table is testable without an IDA
/// install, which is exactly the environment that cannot have one.
fn decide(
    core_dir: Option<PathBuf>,
    resource_dir: Option<PathBuf>,
    source: ResourceDirSource,
) -> InstallCheck {
    let Some(resource_dir) = resource_dir else {
        return InstallCheck::Consistent;
    };
    let Some(core_dir) = core_dir else {
        return InstallCheck::Undetermined(
            "could not identify the IDA core library this process loaded",
        );
    };
    if core_dir == resource_dir {
        return InstallCheck::Consistent;
    }
    InstallCheck::Mixed(InstallMismatch {
        core_dir,
        resource_dir,
        source,
    })
}

/// Resolve symlinks so two spellings of one install compare equal.
///
/// Falls back to the path as given when it cannot be resolved: a `$IDADIR` that
/// does not exist is itself worth reporting, and reporting it as a mismatch
/// against the directory that *does* hold IDA says the useful half of that.
fn normalize(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    }
    #[cfg(not(windows))]
    {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }
}

/// The install directory of `raw` when it names one of IDA's core libraries.
///
/// `libida` covers `libida.so`, `libida32.so` and `libida.dylib`; `libidalib` is
/// the idalib entry point installed beside them. Either one answers the only
/// question asked here, which is *which directory*, so the prefix is enough and
/// the per-platform suffixes do not need enumerating.
///
/// Windows names its module `ida.dll` and asks the loader for it by name, so
/// the byte-slice form has no caller there outside this module's own tests.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn core_library_dir(raw: &[u8]) -> Option<PathBuf> {
    let path = path_from_bytes(raw)?;
    let name = path.file_name()?.to_str()?;
    if !name.starts_with("libida") {
        return None;
    }
    path.parent().map(Path::to_path_buf)
}

/// Interpret a loader-owned path as this platform spells paths.
pub(crate) fn path_from_bytes(raw: &[u8]) -> Option<PathBuf> {
    if raw.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        Some(PathBuf::from(std::ffi::OsStr::from_bytes(raw)))
    }
    #[cfg(not(unix))]
    {
        Some(PathBuf::from(String::from_utf8_lossy(raw).into_owned()))
    }
}

/// Where the IDA core library this process loaded actually lives.
///
/// `libida` is a `NEEDED` entry of the binary, so it is in the link map from
/// process start — this needs no `init_library()` and no database.
#[cfg(target_os = "linux")]
pub(crate) fn loaded_core_dir() -> Option<PathBuf> {
    use std::ffi::CStr;

    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        // SAFETY: the loader hands the callback a live `dl_phdr_info` for the
        // duration of the call, and `data` is the `*mut Option<PathBuf>` that
        // `dl_iterate_phdr` was given below.
        let (name, found) = unsafe { ((*info).dlpi_name, &mut *data.cast::<Option<PathBuf>>()) };
        if name.is_null() {
            return 0;
        }
        // SAFETY: `dlpi_name` is a NUL-terminated path owned by the loader and
        // valid for this callback.
        let Some(dir) = core_library_dir(unsafe { CStr::from_ptr(name) }.to_bytes()) else {
            return 0;
        };
        *found = Some(dir);
        // Any non-zero value ends the walk; there is nothing left to look for.
        1
    }

    let mut found: Option<PathBuf> = None;
    // SAFETY: `visit` has the signature `dl_iterate_phdr` expects, and `found`
    // outlives the walk, which completes before this call returns.
    unsafe { libc::dl_iterate_phdr(Some(visit), (&raw mut found).cast()) };
    found
}

/// dyld's image list, declared here rather than taken from `libc`.
///
/// `libc` deprecated both of these in favour of `mach2`, and this crate's
/// clippy gate is `-D warnings`, so using them would fail the build. They are
/// two stable C entry points in libSystem, which every macOS binary links, so
/// declaring them costs one extern block and saves a dependency added for two
/// signatures.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(image_index: u32) -> *const std::ffi::c_char;
}

#[cfg(target_os = "macos")]
pub(crate) fn loaded_core_dir() -> Option<PathBuf> {
    use std::ffi::CStr;

    // SAFETY: the dyld image list only changes under dlopen/dlclose. This runs
    // on the main thread during startup, before any database is opened.
    let count = unsafe { _dyld_image_count() };
    (0..count).find_map(|index| {
        // SAFETY: `index` is below the count read above, and the returned
        // pointer is a NUL-terminated path owned by dyld.
        let name = unsafe { _dyld_get_image_name(index) };
        if name.is_null() {
            return None;
        }
        core_library_dir(unsafe { CStr::from_ptr(name) }.to_bytes())
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn loaded_core_dir() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

    ["ida.dll\0", "idalib.dll\0"].into_iter().find_map(|name| {
        let name: Vec<u16> = name.encode_utf16().collect();
        // SAFETY: `name` is NUL-terminated. `GetModuleHandleW` does not
        // increment a refcount, so the handle needs no release.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        if module.is_null() {
            return None;
        }
        // MAX_PATH is not a limit on module paths; this is the documented
        // ceiling for an extended-length path.
        let mut buffer = vec![0u16; 32_768];
        // SAFETY: `module` is a live module handle and `buffer` is writable for
        // the length passed.
        let written = unsafe {
            GetModuleFileNameW(
                module,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
            )
        };
        let written = usize::try_from(written).ok()?;
        if written == 0 || written >= buffer.len() {
            return None;
        }
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..written]))
            .parent()
            .map(Path::to_path_buf)
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn loaded_core_dir() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::{
        core_library_dir, decide, InstallCheck, InstallMismatch, ResourceDirSource,
        ALLOW_MISMATCH_FLAG,
    };
    use std::path::PathBuf;

    #[test]
    fn a_core_library_yields_its_install_directory() {
        assert_eq!(
            core_library_dir(b"/opt/ida-pro-9.4/libida.so"),
            Some(PathBuf::from("/opt/ida-pro-9.4"))
        );
        assert_eq!(
            core_library_dir(b"/opt/ida-pro-9.4/libidalib.so"),
            Some(PathBuf::from("/opt/ida-pro-9.4"))
        );
        assert_eq!(
            core_library_dir(b"/Applications/IDA Professional 9.4.app/Contents/MacOS/libida.dylib"),
            Some(PathBuf::from(
                "/Applications/IDA Professional 9.4.app/Contents/MacOS"
            ))
        );
    }

    #[test]
    fn every_other_loaded_object_is_ignored() {
        // The walk visits the whole link map, so the predicate has to reject
        // the main executable (an empty name) and every unrelated library.
        assert_eq!(core_library_dir(b""), None);
        assert_eq!(core_library_dir(b"/lib/x86_64-linux-gnu/libc.so.6"), None);
        assert_eq!(core_library_dir(b"/opt/ida-pro-9.4/libz3.so"), None);
    }

    #[test]
    fn one_install_in_two_spellings_is_not_a_mismatch() {
        let dir = PathBuf::from("/opt/ida-pro-9.4");
        assert_eq!(
            decide(Some(dir.clone()), Some(dir), ResourceDirSource::Environment),
            InstallCheck::Consistent
        );
    }

    #[test]
    fn an_unset_resource_dir_leaves_ida_to_derive_it() {
        assert_eq!(
            decide(
                Some(PathBuf::from("/opt/ida-pro-9.4")),
                None,
                ResourceDirSource::Environment
            ),
            InstallCheck::Consistent
        );
    }

    #[test]
    fn an_unlocatable_core_library_is_not_a_finding() {
        // Stub builds link no IDA at all. Refusing to start there would break
        // CI over a question that has no answer rather than a bad one.
        assert!(matches!(
            decide(
                None,
                Some(PathBuf::from("/opt/ida-pro-9.3")),
                ResourceDirSource::Environment
            ),
            InstallCheck::Undetermined(_)
        ));
    }

    #[test]
    fn two_installs_are_reported_with_both_directories_and_a_way_out() {
        let InstallCheck::Mixed(mismatch) = decide(
            Some(PathBuf::from("/home/u/ida-pro-9.4")),
            Some(PathBuf::from("/home/u/ida-pro-9.3")),
            ResourceDirSource::Environment,
        ) else {
            panic!("two different install directories must be a mismatch");
        };
        assert_eq!(
            mismatch,
            InstallMismatch {
                core_dir: PathBuf::from("/home/u/ida-pro-9.4"),
                resource_dir: PathBuf::from("/home/u/ida-pro-9.3"),
                source: ResourceDirSource::Environment,
            }
        );

        // The message is the deliverable: a reader who arrived here from
        // "Decompiler not available" has to be able to act on it alone.
        let message = mismatch.to_string();
        assert!(message.contains("/home/u/ida-pro-9.4"), "{message}");
        assert!(message.contains("/home/u/ida-pro-9.3"), "{message}");
        assert!(message.contains("IDADIR"), "{message}");
        assert!(message.contains(ALLOW_MISMATCH_FLAG), "{message}");
    }

    #[test]
    fn the_message_names_where_the_resource_directory_came_from() {
        let ida = decide(
            Some(PathBuf::from("/a")),
            Some(PathBuf::from("/b")),
            ResourceDirSource::Ida,
        );
        let InstallCheck::Mixed(mismatch) = ida else {
            panic!("expected a mismatch");
        };
        assert!(mismatch.to_string().contains("idadir()"));
    }
}
