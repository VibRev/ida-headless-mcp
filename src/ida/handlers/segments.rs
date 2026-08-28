//! Segment-related handlers.

use crate::error::ToolError;
use crate::ida::types::SegmentInfo;
use idalib::IDB;

pub fn handle_segments(idb: &Option<IDB>) -> Result<Vec<SegmentInfo>, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let mut segments = Vec::new();
    for (_id, seg) in db.segments() {
        let perms = seg.permissions();
        let perm_str = format!(
            "{}{}{}",
            if perms.is_readable() { "r" } else { "-" },
            if perms.is_writable() { "w" } else { "-" },
            if perms.is_executable() { "x" } else { "-" }
        );

        segments.push(SegmentInfo {
            name: seg.name().unwrap_or_default(),
            start: format!("{:#x}", seg.start_address()),
            end: format!("{:#x}", seg.end_address()),
            size: seg.len(),
            permissions: perm_str,
            r#type: format!("{:?}", seg.r#type()),
            bitness: seg.bitness() as u32,
        });
    }

    Ok(segments)
}
