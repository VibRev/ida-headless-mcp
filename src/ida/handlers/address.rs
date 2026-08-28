//! Address context handlers.

use crate::error::ToolError;
use crate::ida::types::{AddressInfo, FunctionRangeInfo, SegmentInfo, SymbolInfo};
use idalib::IDB;

pub fn handle_addr_info(idb: &Option<IDB>, addr: u64) -> Result<AddressInfo, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;

    let segment = db.segment_at(addr).map(|seg| {
        let perms = seg.permissions();
        let perm_str = format!(
            "{}{}{}",
            if perms.is_readable() { "r" } else { "-" },
            if perms.is_writable() { "w" } else { "-" },
            if perms.is_executable() { "x" } else { "-" }
        );

        SegmentInfo {
            name: seg.name().unwrap_or_default(),
            start: format!("{:#x}", seg.start_address()),
            end: format!("{:#x}", seg.end_address()),
            size: seg.len(),
            permissions: perm_str,
            r#type: format!("{:?}", seg.r#type()),
            bitness: seg.bitness() as u32,
        }
    });

    let function = db.function_at(addr).map(|func| {
        let start = func.start_address();
        let end = func.end_address();
        let name = func.name().unwrap_or_else(|| format!("sub_{:x}", start));
        FunctionRangeInfo {
            address: format!("{:#x}", start),
            name,
            start: format!("{:#x}", start),
            end: format!("{:#x}", end),
            size: func.len(),
        }
    });

    let symbol = db.names().get_closest_by_address(addr).map(|name| {
        let sym_addr = name.address();
        let delta_raw: i128 = if addr >= sym_addr {
            (addr - sym_addr) as i128
        } else {
            -((sym_addr - addr) as i128)
        };
        let delta = delta_raw.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        SymbolInfo {
            name: name.name().to_string(),
            address: format!("{:#x}", sym_addr),
            delta,
            exact: delta == 0,
            is_public: name.is_public(),
            is_weak: name.is_weak(),
        }
    });

    Ok(AddressInfo {
        address: format!("{:#x}", addr),
        segment,
        function,
        symbol,
    })
}
