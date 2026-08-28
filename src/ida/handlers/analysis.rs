//! Analysis status helpers.

use crate::error::ToolError;
use crate::ida::types::AnalysisStatus;
use idalib::IDB;

fn auto_state_name(state: i32) -> &'static str {
    match state {
        0 => "AU_NONE",
        10 => "AU_UNK",
        20 => "AU_CODE",
        25 => "AU_WEAK",
        30 => "AU_PROC",
        35 => "AU_TAIL",
        38 => "AU_FCHUNK",
        40 => "AU_USED",
        45 => "AU_USD2",
        50 => "AU_TYPE",
        60 => "AU_LIBF",
        70 => "AU_LBF2",
        80 => "AU_LBF3",
        90 => "AU_CHLB",
        200 => "AU_FINAL",
        _ => "AU_UNKNOWN",
    }
}

pub fn build_analysis_status(db: &IDB) -> AnalysisStatus {
    let meta = db.meta();
    let auto_enabled = meta.is_auto_enabled();
    let auto_is_ok = meta.auto_is_ok();
    let auto_state_id = meta.auto_state();
    AnalysisStatus {
        auto_enabled,
        auto_is_ok,
        auto_state: auto_state_name(auto_state_id).to_string(),
        auto_state_id,
        analysis_running: auto_enabled && !auto_is_ok,
    }
}

pub fn handle_analysis_status(idb: &Option<IDB>) -> Result<AnalysisStatus, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Ok(build_analysis_status(db))
}
