use std::env;
use std::path::{Path, PathBuf};

#[cfg(not(any(feature = "ida-92", feature = "ida-93", feature = "ida-94")))]
compile_error!("enable exactly one IDA SDK feature: ida-92, ida-93, or ida-94");
#[cfg(any(
    all(feature = "ida-92", feature = "ida-93"),
    all(feature = "ida-92", feature = "ida-94"),
    all(feature = "ida-93", feature = "ida-94"),
))]
compile_error!("IDA SDK features are mutually exclusive");

#[cfg(feature = "ida-92")]
use idalib_build_92 as selected_idalib_build;
#[cfg(feature = "ida-93")]
use idalib_build_93 as selected_idalib_build;
#[cfg(feature = "ida-94")]
use idalib_build_94 as selected_idalib_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Re-run linkage (rpath embedding) whenever the targeted IDA install changes.
    println!("cargo::rerun-if-env-changed=IDADIR");

    // Independent of everything IDA-related below, and cheap: do it first so a
    // malformed skill fails the build before the C++ bridge spends a minute.
    // The walking, the frontmatter validation, the fingerprint and the archive
    // are `vibrev-skills`; what stays here is which directory to walk.
    vibrev_skills::pack::pack(&source_root())?;

    let (install_path, ida_path, idalib_path) =
        selected_idalib_build::idalib_install_paths_with(false);

    let using_sdk_stubs = !ida_path.exists() || !idalib_path.exists();
    if using_sdk_stubs {
        if requires_local_ida_install() {
            return Err(
                "IDA installation not found for a target that requires local IDA libraries".into(),
            );
        }
        println!("cargo::warning=IDA installation not found, using SDK stubs");
        selected_idalib_build::configure_idasdk_linkage();
    } else {
        // Configure linkage to IDA libraries
        selected_idalib_build::configure_linkage()?;
    }

    // Compile the C crash guard (sigsetjmp-based signal isolation)
    #[cfg(unix)]
    {
        let crash_guard = source_root().join("src/crash_guard.c");
        println!("cargo::rerun-if-changed={}", crash_guard.display());
        cc::Build::new()
            .file(crash_guard)
            .warnings(false)
            .compile("crash_guard");
    }

    // Compile the small, stable C ABI used for SDK operations that idalib does
    // not expose yet.
    let (sdk_path, _, _, _) = selected_idalib_build::idalib_sdk_paths_with(false);
    let sdk_bridge = source_root().join("src/ida_sdk_bridge.cpp");
    println!("cargo::rerun-if-changed={}", sdk_bridge.display());
    let mut bridge = cc::Build::new();
    bridge
        .cpp(true)
        .file(sdk_bridge)
        .include(sdk_path.join("include"))
        .warnings(false)
        .define("__EA64__", "1");
    configure_sdk_bridge(&mut bridge);
    bridge.compile("ida_mcp_sdk_bridge");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo::rustc-link-lib=dl");
    }

    // Always set rpaths for runtime library discovery.
    // This adds the specified install path plus common default locations
    // so the binary can find IDA libraries without DYLD_LIBRARY_PATH.
    set_rpath(&install_path, using_sdk_stubs);

    Ok(())
}

fn configure_sdk_bridge(build: &mut cc::Build) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| env::consts::OS.to_string());
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| env::consts::ARCH.to_string());
    match os.as_str() {
        "linux" => {
            build
                .define("__LINUX__", "1")
                .flag_if_supported("-std=c++17");
        }
        "macos" => {
            build
                .define("__MACOS__", "1")
                .flag_if_supported("-std=c++17");
            if arch == "aarch64" {
                build.define("__ARM__", "1");
            }
        }
        "windows" => {
            build.define("__NT__", "1").flag_if_supported("/std:c++17");
        }
        _ => panic!("unsupported target OS: {os}"),
    }
}

fn source_root() -> PathBuf {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo always sets CARGO_MANIFEST_DIR"),
    );
    if manifest_dir.join("src/crash_guard.c").is_file() {
        manifest_dir
    } else {
        manifest_dir.join("../..")
    }
}

#[cfg(feature = "ida-92")]
fn requires_local_ida_install() -> bool {
    false
}

#[cfg(any(feature = "ida-93", feature = "ida-94"))]
fn requires_local_ida_install() -> bool {
    selected_idalib_build::requires_local_ida_install()
}

/// Set rpath to the IDA installation directory for runtime library loading.
/// Adds multiple common IDA installation paths so the binary can find libraries
/// without requiring DYLD_LIBRARY_PATH to be set.
fn set_rpath(install_path: &Path, include_install_path: bool) {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| {
        if cfg!(target_os = "macos") {
            "macos".to_string()
        } else if cfg!(target_os = "linux") {
            "linux".to_string()
        } else {
            "unknown".to_string()
        }
    });

    // configure_linkage() already adds the selected runtime path when a local
    // IDA install is present. Stub builds still need us to add it explicitly.
    if include_install_path {
        add_rpath(install_path);
    }

    let targeting_94 = cfg!(feature = "ida-94");

    if os == "macos" {
        // Common macOS IDA installation paths (all editions)
        let default_paths: &[&str] = if targeting_94 {
            &[
                "/Applications/IDA Professional 9.4.app/Contents/MacOS",
                "/Applications/IDA Pro 9.4.app/Contents/MacOS",
                "/Applications/IDA Home 9.4.app/Contents/MacOS",
                "/Applications/IDA Essential 9.4.app/Contents/MacOS",
            ]
        } else {
            &[
                // IDA 9.3 paths
                "/Applications/IDA Professional 9.3.app/Contents/MacOS",
                "/Applications/IDA Pro 9.3.app/Contents/MacOS",
                "/Applications/IDA Home 9.3.app/Contents/MacOS",
                "/Applications/IDA Essential 9.3.app/Contents/MacOS",
                // IDA 9.2 paths
                "/Applications/IDA Professional 9.2.app/Contents/MacOS",
                "/Applications/IDA Pro 9.2.app/Contents/MacOS",
                "/Applications/IDA Home 9.2.app/Contents/MacOS",
                "/Applications/IDA Essential 9.2.app/Contents/MacOS",
            ]
        };
        for path in default_paths {
            add_rpath_if_not_install(Path::new(path), install_path);
        }
    } else if os == "linux" {
        // Common Linux IDA installation paths
        let home = env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
        let default_paths = if targeting_94 {
            vec![
                format!("{home}/idapro-9.4"),
                format!("{home}/ida-pro-9.4"),
                "/opt/idapro-9.4".to_string(),
                "/opt/ida-pro-9.4".to_string(),
                "/usr/local/idapro-9.4".to_string(),
            ]
        } else {
            vec![
                // IDA 9.3 paths
                format!("{}/idapro-9.3", home),
                format!("{}/ida-pro-9.3", home),
                "/opt/idapro-9.3".to_string(),
                "/opt/ida-pro-9.3".to_string(),
                "/usr/local/idapro-9.3".to_string(),
                // IDA 9.2 paths
                format!("{}/idapro-9.2", home),
                format!("{}/ida-pro-9.2", home),
                "/opt/idapro-9.2".to_string(),
                "/opt/ida-pro-9.2".to_string(),
                "/usr/local/idapro-9.2".to_string(),
            ]
        };
        for path in default_paths {
            add_rpath_if_not_install(Path::new(&path), install_path);
        }
    }
}

fn add_rpath_if_not_install(path: &Path, install_path: &Path) {
    if path != install_path {
        add_rpath(path);
    }
}

fn add_rpath(path: &Path) {
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", path.display());
}
