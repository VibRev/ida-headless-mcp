//! Post-open warmup: rebuild caches and initialize Hex-Rays.

use crate::error::ToolError;
use crate::ida::handlers::strings::rebuild_string_index;
use crate::ida::sdk_bridge;
use crate::ida::types::{WarmupResult, WarmupStep};
use idalib::IDB;
use std::time::Instant;

pub const BUILD_CACHES_STEP: &str = "build_caches";
pub const INIT_HEXRAYS_STEP: &str = "init_hexrays";

const HEXRAYS_UNAVAILABLE: &str = "Hex-Rays decompiler is not available";

pub fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub fn handle_warmup(
    idb: &Option<IDB>,
    build_caches: bool,
    init_hexrays: bool,
) -> Result<WarmupResult, ToolError> {
    if !build_caches && !init_hexrays {
        return Ok(WarmupResult::from_steps(Vec::new()));
    }
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let mut steps = Vec::new();
    if build_caches {
        steps.push(run_build_caches(db));
    }
    if init_hexrays {
        steps.push(run_init_hexrays());
    }
    Ok(WarmupResult::from_steps(steps))
}

fn run_build_caches(db: &IDB) -> WarmupStep {
    let started = Instant::now();
    rebuild_string_index(db);
    WarmupStep::ok(BUILD_CACHES_STEP, elapsed_ms(started))
}

fn run_init_hexrays() -> WarmupStep {
    let started = Instant::now();
    if sdk_bridge::init_hexrays() {
        WarmupStep::ok(INIT_HEXRAYS_STEP, elapsed_ms(started))
    } else {
        WarmupStep::err(INIT_HEXRAYS_STEP, elapsed_ms(started), HEXRAYS_UNAVAILABLE)
    }
}

/// Map a child `decompile` error onto Hex-Rays warmup success or failure.
///
/// Pooled sessions cannot send [`crate::ida::request::IdaRequest::Warmup`]
/// without a public MCP tool, so they probe via `decompile`. That handler
/// checks `decompiler_available()` before looking up a function: "function not
/// found" means the plugin answered, "decompiler not available" is a real miss.
pub fn classify_hexrays_probe(error: &ToolError) -> Result<(), String> {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("decompiler not available") {
        Err(HEXRAYS_UNAVAILABLE.to_string())
    } else if lowered.contains("function not found") || lowered.contains("outside valid range") {
        Ok(())
    } else {
        Err(message)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_hexrays_probe, handle_warmup, BUILD_CACHES_STEP, HEXRAYS_UNAVAILABLE,
        INIT_HEXRAYS_STEP,
    };
    use crate::error::ToolError;
    use crate::ida::types::{WarmupResult, WarmupStep};
    use serde_json::json;

    #[test]
    fn disabled_flags_do_not_emit_warmup_steps() {
        let result = handle_warmup(&None, false, false).expect("no-op warmup");
        assert!(result.ok);
        assert!(result.steps.is_empty());
        assert!(!result
            .steps
            .iter()
            .any(|step| step.step == BUILD_CACHES_STEP || step.step == INIT_HEXRAYS_STEP));
    }

    #[test]
    fn enabled_warmup_without_a_database_is_an_error() {
        let err = handle_warmup(&None, true, false).expect_err("needs an open database");
        assert!(matches!(err, ToolError::NoDatabaseOpen));
        let err = handle_warmup(&None, false, true).expect_err("needs an open database");
        assert!(matches!(err, ToolError::NoDatabaseOpen));
    }

    #[test]
    fn hexrays_failure_is_ok_false_with_error_and_never_lazy() {
        let step = WarmupStep::err(INIT_HEXRAYS_STEP, 4, HEXRAYS_UNAVAILABLE);
        let value = serde_json::to_value(WarmupResult::from_steps(vec![step])).expect("serialize");
        assert_eq!(
            value,
            json!({
                "ok": false,
                "steps": [{
                    "step": "init_hexrays",
                    "ok": false,
                    "ms": 4,
                    "error": HEXRAYS_UNAVAILABLE
                }]
            })
        );
        assert!(value["steps"][0].get("lazy").is_none());
    }

    #[test]
    fn hexrays_probe_treats_missing_function_as_plugin_ready() {
        assert!(classify_hexrays_probe(&ToolError::FunctionNotFound(0)).is_ok());
        assert!(classify_hexrays_probe(&ToolError::AddressOutOfRange(u64::MAX)).is_ok());
        assert_eq!(
            classify_hexrays_probe(&ToolError::DecompilerUnavailable).unwrap_err(),
            HEXRAYS_UNAVAILABLE
        );
        assert_eq!(
            classify_hexrays_probe(&ToolError::IdaError(
                "Function not found at address 0xffffffffffffffff".to_string()
            ))
            .ok(),
            Some(())
        );
        assert_eq!(
            classify_hexrays_probe(&ToolError::IdaError("Decompiler not available".to_string()))
                .unwrap_err(),
            HEXRAYS_UNAVAILABLE
        );
    }
}
