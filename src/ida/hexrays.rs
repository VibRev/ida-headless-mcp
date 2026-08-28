//! Why the decompiler is unavailable, when it is.
//!
//! "Hex-Rays decompiler is not available" was the whole of what this engine used
//! to say, and it covers at least five unrelated situations: no module for this
//! processor, a module that is not installed, a core library paired with another
//! install's plugins, a licence that does not cover the decompiler, and a plugin
//! that simply declined. A reader cannot act on the sentence without guessing
//! which one they have.
//!
//! So this module reports observations rather than a verdict. Every field below
//! is something that was actually looked up on the failure path; nothing is
//! inferred from the absence of something else, and the summary sentence names
//! the most specific fact the observations support rather than the most likely
//! cause.

use std::path::{Path, PathBuf};

use idalib::IDB;
use serde::Serialize;

use crate::error::ToolError;
use crate::ida::{install, sdk_bridge};

/// What was true about the decompiler at the moment it was asked for.
#[derive(Debug, Clone, Serialize)]
pub struct HexraysDiagnostics {
    /// IDA SDK this binary was compiled against.
    sdk_version: String,
    /// Version the loaded IDA core reports, when it answers at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_version: Option<String>,
    /// Directory the core library was loaded from.
    #[serde(skip_serializing_if = "Option::is_none")]
    core_dir: Option<PathBuf>,
    /// Directory IDA reads its plugins from.
    #[serde(skip_serializing_if = "Option::is_none")]
    plugins_dir: Option<PathBuf>,
    /// Processor as IDA names it, and the bitness of the application.
    #[serde(skip_serializing_if = "Option::is_none")]
    processor: Option<String>,
    bitness: u32,
    /// Module this processor needs, when a name is known for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_module: Option<&'static str>,
    /// Decompiler modules actually installed, so a wrong edition is visible
    /// rather than merely suspected.
    installed_modules: Vec<String>,
    /// IDA's own licence verdict — *not* the decompiler add-on, which has no
    /// separate query. Named this way so the distinction survives the hop.
    #[serde(skip_serializing_if = "Option::is_none")]
    ida_license_valid: Option<bool>,
    /// The two halves of the installation disagreeing, when they do.
    #[serde(skip_serializing_if = "Option::is_none")]
    install_mismatch: Option<String>,
}

impl HexraysDiagnostics {
    /// Look up everything observable about the decompiler right now.
    ///
    /// Only called once a probe has already failed, so the directory read and
    /// the licence query are off the hot path.
    pub fn collect(db: &IDB) -> Self {
        let meta = db.meta();
        let processor = meta.procname();
        let bitness = meta.app_bitness();
        let plugins_dir = sdk_bridge::idadir().map(|dir| dir.join("plugins"));
        Self {
            sdk_version: format!("{}.{}", idalib::SDK_VERSION.0, idalib::SDK_VERSION.1),
            runtime_version: idalib::version().ok().map(|version| version.to_string()),
            core_dir: install::loaded_core_dir(),
            expected_module: decompiler_module(&processor, bitness),
            installed_modules: installed_decompilers(plugins_dir.as_deref()),
            plugins_dir,
            processor: crate::non_empty_trimmed(Some(&processor)).map(str::to_owned),
            bitness,
            ida_license_valid: ida_license_valid(),
            install_mismatch: install::current_mismatch().map(|fault| fault.to_string()),
        }
    }

    /// The most specific thing the observations support, in one sentence.
    ///
    /// Ordered by how much it narrows the search, not by how likely it is: a
    /// mixed install explains every other symptom on this list, so it has to be
    /// said first or the reader will chase the one it caused.
    pub fn summary(&self) -> String {
        if let Some(mismatch) = &self.install_mismatch {
            return format!(
                "the decompiler module would be loaded from an installation other than the one \
                 this process's IDA core came from.\n{mismatch}"
            );
        }
        match (self.expected_module, &self.processor) {
            (Some(module), _) if !self.has_module(module) => format!(
                "IDA's plugin directory has no {module} module for processor {processor}. \
                 It installs: {installed}. That edition of IDA does not ship this decompiler.",
                processor = self.processor_description(),
                installed = self.installed_description(),
            ),
            (None, Some(_)) => format!(
                "no Hex-Rays module is known for processor {processor}. \
                 The installed decompilers are: {installed}.",
                processor = self.processor_description(),
                installed = self.installed_description(),
            ),
            _ if self.ida_license_valid == Some(false) => {
                "IDA reports its own licence as invalid, so no plugin will initialize. \
                 Check ida.hexlic and licence server reachability."
                    .to_owned()
            }
            // Everything checkable checks out, so say exactly that and name the
            // one thing left rather than inventing a sixth possibility. The
            // probe behind this is live on every call — `init_hexrays_plugin()`
            // and `decompiler_available()` both ask IDA — so a stale cache in
            // this server is not among the candidates.
            _ => format!(
                "the {module} module is installed and this process's IDA is internally \
                 consistent, so the plugin itself declined to initialize. The usual cause is an \
                 ida.hexlic that covers IDA but not this decompiler. (The probe is live on every \
                 call, so this is not a cached result.)",
                module = self.expected_module.unwrap_or("Hex-Rays"),
            ),
        }
    }

    /// Turn the observations into an error that survives the supervisor hop.
    ///
    /// The message keeps the words "Decompiler not available" at the front on
    /// purpose: [`crate::ida::handlers::warmup::classify_hexrays_probe`] reads
    /// the message to tell a missing plugin from a missing function, and the
    /// diagnosis is an addition to that contract, not a replacement for it.
    pub fn into_error(self) -> ToolError {
        let message = format!("Decompiler not available: {}", self.summary());
        match serde_json::to_value(&self) {
            Ok(detail) => ToolError::IdaErrorDetail {
                message,
                detail: Box::new(detail),
            },
            // A diagnosis that cannot be serialized is still worth its sentence.
            Err(_) => ToolError::IdaError(message),
        }
    }

    fn has_module(&self, module: &str) -> bool {
        self.installed_modules.iter().any(|name| name == module)
    }

    fn processor_description(&self) -> String {
        let processor = self.processor.as_deref().unwrap_or("(unnamed)");
        format!("{processor} ({}-bit)", self.bitness)
    }

    fn installed_description(&self) -> String {
        if self.installed_modules.is_empty() {
            return "none".to_owned();
        }
        self.installed_modules.join(", ")
    }
}

/// The Hex-Rays module a processor needs, by the file names IDA installs.
///
/// Taken from a real 9.4 tree, which ships `hexarc` (ARM64), `hexarm` (ARM32),
/// `hexx64`, `hexmips`, `hexppc`, `hexrv` and `hexv850` — and, tellingly, no
/// x86-32 decompiler, because that is a separate purchase. `hexrays` is the
/// historical name for that one and is the single entry here not confirmed
/// against a local install; a caller misled by it still sees the truth, because
/// every message that uses this mapping also lists what is actually installed.
///
/// `None` is a real answer: it means no module name is known for the processor,
/// which is worth reporting rather than papering over with a guess.
fn decompiler_module(procname: &str, bitness: u32) -> Option<&'static str> {
    let procname = procname.trim().to_ascii_lowercase();
    match (procname.as_str(), bitness) {
        ("arm", 64) | ("arm64", _) | ("aarch64", _) => Some("hexarc"),
        ("arm", _) => Some("hexarm"),
        ("metapc", 64) | ("x86_64", _) => Some("hexx64"),
        ("metapc", _) => Some("hexrays"),
        ("ppc", _) => Some("hexppc"),
        ("riscv", _) => Some("hexrv"),
        ("v850", _) | ("nec850", _) => Some("hexv850"),
        (other, _) if other.starts_with("mips") => Some("hexmips"),
        _ => None,
    }
}

/// Decompiler modules present in `plugins_dir`, by bare name.
///
/// Reads the directory rather than probing known names so an install carrying a
/// module this engine has never heard of still shows up.
fn installed_decompilers(plugins_dir: Option<&Path>) -> Vec<String> {
    let Some(dir) = plugins_dir else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut modules: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let stem = Path::new(&name).file_stem()?.to_str()?;
            stem.starts_with("hex").then(|| stem.to_owned())
        })
        .collect();
    modules.sort_unstable();
    modules.dedup();
    modules
}

/// IDA's licence verdict, or `None` when this SDK cannot be asked.
#[cfg(not(feature = "ida-92"))]
fn ida_license_valid() -> Option<bool> {
    idalib::is_valid_license().ok()
}

#[cfg(feature = "ida-92")]
fn ida_license_valid() -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::{decompiler_module, HexraysDiagnostics};
    use crate::error::ToolError;

    #[test]
    fn each_processor_maps_to_the_module_ida_installs_for_it() {
        assert_eq!(decompiler_module("ARM", 64), Some("hexarc"));
        assert_eq!(decompiler_module("ARM", 32), Some("hexarm"));
        assert_eq!(decompiler_module("metapc", 64), Some("hexx64"));
        assert_eq!(decompiler_module("mipsb", 32), Some("hexmips"));
        assert_eq!(decompiler_module("mipsl", 64), Some("hexmips"));
        assert_eq!(decompiler_module("PPC", 32), Some("hexppc"));
        assert_eq!(decompiler_module("RISCV", 64), Some("hexrv"));
        assert_eq!(decompiler_module("V850", 32), Some("hexv850"));
    }

    #[test]
    fn an_unmapped_processor_is_reported_rather_than_guessed() {
        assert_eq!(decompiler_module("6502", 16), None);
        assert_eq!(decompiler_module("", 32), None);
    }

    /// An arm64 database on a healthy install, for tests to spoil one field at
    /// a time. Every case below is "this one observation differs", so the
    /// baseline has to be the case where nothing is wrong but the plugin.
    fn healthy_arm64() -> HexraysDiagnostics {
        HexraysDiagnostics {
            sdk_version: "9.4".to_owned(),
            runtime_version: Some("9.4.260714".to_owned()),
            core_dir: None,
            plugins_dir: None,
            processor: Some("ARM".to_owned()),
            bitness: 64,
            expected_module: Some("hexarc"),
            installed_modules: vec!["hexarc".to_owned(), "hexx64".to_owned()],
            ida_license_valid: Some(true),
            install_mismatch: None,
        }
    }

    #[test]
    fn a_mixed_install_is_named_before_anything_it_would_explain() {
        // A mixed install also makes the module look absent and the plugin look
        // broken. Reporting either of those first sends the reader after a
        // symptom, so the mismatch has to win even when the rest looks wrong.
        let summary = HexraysDiagnostics {
            installed_modules: Vec::new(),
            install_mismatch: Some("core is 9.4, plugins are 9.3".to_owned()),
            ..healthy_arm64()
        }
        .summary();
        assert!(summary.contains("plugins are 9.3"), "{summary}");
    }

    #[test]
    fn a_missing_module_names_both_what_is_wanted_and_what_is_there() {
        let summary = HexraysDiagnostics {
            processor: Some("metapc".to_owned()),
            expected_module: Some("hexx64"),
            installed_modules: vec!["hexarc".to_owned(), "hexarm".to_owned()],
            ..healthy_arm64()
        }
        .summary();
        assert!(summary.contains("hexx64"), "{summary}");
        assert!(summary.contains("hexarc, hexarm"), "{summary}");
    }

    #[test]
    fn an_unknown_processor_says_so_instead_of_blaming_the_licence() {
        let summary = HexraysDiagnostics {
            processor: Some("6502".to_owned()),
            bitness: 16,
            expected_module: None,
            ..healthy_arm64()
        }
        .summary();
        assert!(summary.contains("6502 (16-bit)"), "{summary}");
        assert!(!summary.contains("licence"), "{summary}");
    }

    #[test]
    fn an_invalid_ida_licence_outranks_the_add_on_guess() {
        let summary = HexraysDiagnostics {
            ida_license_valid: Some(false),
            ..healthy_arm64()
        }
        .summary();
        assert!(summary.contains("ida.hexlic"), "{summary}");
        assert!(summary.contains("invalid"), "{summary}");
    }

    #[test]
    fn an_installed_module_that_still_declined_points_at_the_add_on_licence() {
        let summary = healthy_arm64().summary();
        assert!(summary.contains("hexarc"), "{summary}");
        assert!(summary.contains("ida.hexlic"), "{summary}");
        // The live probe is worth stating: "the server cached a stale answer"
        // is the one candidate a reader cannot rule out from the outside.
        assert!(summary.contains("not a cached result"), "{summary}");
    }

    #[test]
    fn the_error_keeps_the_phrase_the_warmup_classifier_reads() {
        let error = healthy_arm64().into_error();
        let message = error.to_string();
        assert!(
            message
                .to_ascii_lowercase()
                .contains("decompiler not available"),
            "{message}"
        );
        // The observations have to survive as structured data too, or the
        // supervisor hop flattens the diagnosis back to one sentence.
        let ToolError::IdaErrorDetail { detail, .. } = &error else {
            panic!("a diagnosis must carry its observations: {error}");
        };
        assert_eq!(detail["expected_module"], "hexarc");
        assert_eq!(detail["processor"], "ARM");
    }
}
