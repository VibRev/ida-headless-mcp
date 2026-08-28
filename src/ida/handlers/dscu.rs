//! Native IDA 9.4 dyld_shared_cache helpers.

use crate::error::ToolError;
use crate::ida::query::{DscDepsQuery, DscImageQuery, DscStringSearch, DscSymbolSearch};
use crate::ida::types::{
    DscImageDeps, DscImageInfo, DscImageList, DscRegionInfo, DscRegionQuery, DscStringMatches,
    DscSymbolMatches,
};
use idalib::IDB;

#[cfg(feature = "ida-94")]
use crate::ida::query::{dsc_paginate, dsc_scan_count, DscStringScope};
#[cfg(feature = "ida-94")]
use crate::ida::types::{DscStringMatch, DscSymbolMatch};

#[cfg(feature = "ida-94")]
fn require_dscu(idb: &Option<IDB>) -> Result<(), ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if idalib::dscu::is_available() {
        return Ok(());
    }
    Err(ToolError::NotSupported(dscu_unavailable_reason(
        db.meta().input_file_path().trim_end_matches('\0'),
    )))
}

/// Say which of the two ways a database can lack `dscu` this one is, and what
/// follows from it.
///
/// The distinction is not cosmetic. `dscu` is owned by IDA's shared-cache
/// *loader* and lives for as long as the cache is open; a database saved from
/// that session and reopened later is a perfectly good database that simply has
/// no loader attached any more. Nothing on this side can re-attach one — it is
/// not a cache this engine dropped — so the honest answer is to name the file
/// to reopen and to say what still works, rather than to imply a broken setup.
#[cfg(feature = "ida-94")]
fn dscu_unavailable_reason(input_file_path: &str) -> String {
    let input = crate::non_empty_trimmed(Some(input_file_path));
    let looks_like_a_cache = input.is_some_and(|path| {
        std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("dyld_shared_cache"))
    });
    if !looks_like_a_cache {
        return format!(
            "The dsc_* tools need a dyld_shared_cache, and this database was not created from \
             one (input file: {input}). Nothing is wrong with the database — every other tool \
             applies to it normally.",
            input = input.unwrap_or("unknown"),
        );
    }
    format!(
        "IDA's dscu service is not attached to this database. It belongs to the shared-cache \
         loader and only exists while the cache itself is open, so reopening a saved .i64 does \
         not bring it back — this database was created from {input}. To use dsc_list_images, \
         dsc_add_dylib or dsc_find_symbols, open that cache again rather than this .i64. \
         Everything else — disassembly, decompilation, xrefs, strings, renaming — works on this \
         database as it stands.",
        input = input.unwrap_or("the shared cache"),
    )
}

#[cfg(feature = "ida-94")]
fn hex_addr(addr: u64) -> String {
    format!("0x{addr:x}")
}

#[cfg(feature = "ida-94")]
fn image_info(info: idalib::dscu::ImageInfo) -> DscImageInfo {
    DscImageInfo {
        index: info.index,
        name: info.name,
        file_name: info.file_name,
        address: hex_addr(info.address),
        address_value: info.address,
        total_size: info.total_size,
        file_index: info.file_index,
        loaded: info.loaded,
    }
}

#[cfg(feature = "ida-94")]
fn region_kind(kind: idalib::dscu::RegionKind) -> String {
    let kind = match kind {
        idalib::dscu::RegionKind::ImageEntity => "image_entity",
        idalib::dscu::RegionKind::Island => "island",
        idalib::dscu::RegionKind::Header => "header",
        idalib::dscu::RegionKind::Mapping => "mapping",
        idalib::dscu::RegionKind::Unknown => "unknown",
        idalib::dscu::RegionKind::Got => "got",
        idalib::dscu::RegionKind::CacheData => "cache_data",
        idalib::dscu::RegionKind::Invalid(raw) => return format!("invalid({raw})"),
    };
    kind.to_string()
}

#[cfg(feature = "ida-94")]
fn region_info(info: idalib::dscu::RegionInfo) -> DscRegionInfo {
    DscRegionInfo {
        start: hex_addr(info.start),
        start_value: info.start,
        size: info.size,
        kind: region_kind(info.kind),
        image_index: info.image_index,
        name: info.name,
        loaded: info.loaded,
    }
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_load_image(idb: &Option<IDB>, module: &str) -> Result<DscImageInfo, ToolError> {
    require_dscu(idb)?;
    idalib::dscu::load_image(module)
        .map(image_info)
        .map_err(ToolError::from)
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_load_region(idb: &Option<IDB>, ea: u64) -> Result<DscRegionInfo, ToolError> {
    require_dscu(idb)?;
    idalib::dscu::load_region(ea)
        .map(region_info)
        .map_err(ToolError::from)
}

#[cfg(feature = "ida-94")]
fn symbol_flags(search: &DscSymbolSearch) -> u32 {
    use idalib::dscu::symbol_flags as bits;
    let mut flags = 0;
    if search.loaded_images_only {
        flags |= bits::LOADED_IMAGES_ONLY;
    }
    if search.case_insensitive {
        flags |= bits::CASE_INSENSITIVE;
    }
    flags
}

/// Translate the scope and its knobs into `FSSF_*`.
///
/// The two scopes take disjoint knobs, so each arm sets only its own: passing
/// `FILES_INCLUDE_*` under the images scope would be meaningless, not additive.
#[cfg(feature = "ida-94")]
fn string_flags(search: &DscStringSearch) -> u32 {
    use idalib::dscu::string_flags as bits;
    let mut flags = match search.scope {
        DscStringScope::Images => bits::SCOPE_IMAGES,
        DscStringScope::Files => bits::SCOPE_FILES,
    };
    match search.scope {
        DscStringScope::Images => {
            if search.all_sections {
                flags |= bits::IMAGES_SCOPE_ALL;
            }
        }
        DscStringScope::Files => {
            if search.include_symbols {
                flags |= bits::FILES_INCLUDE_SYMBOLS;
            }
            if search.include_branch_mappings {
                flags |= bits::FILES_INCLUDE_BRANCH_MAPPINGS;
            }
            if search.include_other {
                flags |= bits::FILES_INCLUDE_OTHER;
            }
        }
    }
    if search.case_insensitive {
        flags |= bits::CASE_INSENSITIVE;
    }
    flags
}

#[cfg(feature = "ida-94")]
fn symbol_match(value: idalib::dscu::SymbolMatch) -> DscSymbolMatch {
    DscSymbolMatch {
        symbol: value.symbol,
        address: hex_addr(value.address),
        address_value: value.address,
        image_index: value.image_index,
        // -1 is the cache's own .symbols table, which has no image to name.
        image_name: (value.image_index >= 0)
            .then(|| idalib::dscu::image_info(value.image_index))
            .flatten()
            .map(|info| info.name),
    }
}

#[cfg(feature = "ida-94")]
fn string_match(value: idalib::dscu::StringMatch) -> DscStringMatch {
    DscStringMatch {
        address: hex_addr(value.address),
        address_value: value.address,
        image_index: value.image_index,
        file_index: value.file_index,
        file_offset: value.file_offset,
        context: value.context,
    }
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_images(
    idb: &Option<IDB>,
    query: &DscImageQuery,
) -> Result<DscImageList, ToolError> {
    require_dscu(idb)?;
    let filter = query.name_filter()?;
    let matched: Vec<DscImageInfo> = idalib::dscu::images()
        .map_err(ToolError::from)?
        .into_iter()
        .filter(|image| !query.loaded_only || image.loaded)
        .filter(|image| filter.matches(&image.name))
        .map(image_info)
        .collect();
    let total = matched.len();
    let (images, next_offset) = dsc_paginate(matched, query.offset, query.limit);
    Ok(DscImageList {
        images,
        total,
        next_offset,
        input_file_path: idalib::dscu::input_file_path(),
    })
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_image_deps(
    idb: &Option<IDB>,
    query: &DscDepsQuery,
) -> Result<DscImageDeps, ToolError> {
    require_dscu(idb)?;
    let Some(index) = idalib::dscu::image_index(&query.module).map_err(ToolError::from)? else {
        return Err(ToolError::InvalidParams(format!(
            "DSC image not found: {}",
            query.module
        )));
    };
    let all: Vec<DscImageInfo> = idalib::dscu::image_dependencies(index, query.depth)
        .map_err(ToolError::from)?
        .into_iter()
        .map(image_info)
        .collect();
    let total = all.len();
    let (images, next_offset) = dsc_paginate(all, query.offset, query.limit);
    Ok(DscImageDeps {
        images,
        total,
        next_offset,
        module: query.module.clone(),
        depth: query.depth,
    })
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_find_symbols(
    idb: &Option<IDB>,
    search: &DscSymbolSearch,
) -> Result<DscSymbolMatches, ToolError> {
    require_dscu(idb)?;
    let scan = dsc_scan_count(search.offset, search.limit);
    // IDA answers "nothing matched" with a false return rather than a failure
    // (dscu.h: "return true if at least one symbol was found"), and idalib maps
    // that false onto an Err. require_dscu has already proved the service is
    // there, so an Err here is an empty result, not a broken query.
    let found = idalib::dscu::find_symbols(&search.needle, symbol_flags(search), Some(scan))
        .unwrap_or_default();
    let (page, next_offset) = dsc_paginate(found, search.offset, search.limit);
    Ok(DscSymbolMatches {
        matches: page.into_iter().map(symbol_match).collect(),
        next_offset,
    })
}

#[cfg(feature = "ida-94")]
pub fn handle_dsc_find_strings(
    idb: &Option<IDB>,
    search: &DscStringSearch,
) -> Result<DscStringMatches, ToolError> {
    require_dscu(idb)?;
    let scan = dsc_scan_count(search.offset, search.limit);
    // Same "false means empty" contract as handle_dsc_find_symbols.
    let found = idalib::dscu::find_strings(&search.needle, string_flags(search), Some(scan))
        .unwrap_or_default();
    let (page, next_offset) = dsc_paginate(found, search.offset, search.limit);
    Ok(DscStringMatches {
        matches: page.into_iter().map(string_match).collect(),
        next_offset,
    })
}

/// Resolve an address to its region without mapping anything.
///
/// Returns [`DscRegionQuery`] rather than [`DscRegionInfo`]: idalib's query path
/// hardcodes `loaded` to false, so that field would be noise here.
#[cfg(feature = "ida-94")]
pub fn handle_dsc_region_at(idb: &Option<IDB>, ea: u64) -> Result<DscRegionQuery, ToolError> {
    require_dscu(idb)?;
    let info = idalib::dscu::region_by_ea(ea).map_err(ToolError::from)?;
    Ok(DscRegionQuery {
        start: hex_addr(info.start),
        start_value: info.start,
        size: info.size,
        kind: region_kind(info.kind),
        image_index: info.image_index,
        name: info.name,
    })
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_load_image(idb: &Option<IDB>, _module: &str) -> Result<DscImageInfo, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Native DSC module loading requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_load_region(idb: &Option<IDB>, _ea: u64) -> Result<DscRegionInfo, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Native DSC region loading requires an IDA 9.4 build".to_string(),
    ))
}

// The queries below read `dscu_svc_t`, which the 9.2 and 9.3 SDKs do not ship
// at all — no dscu.h, no get_dscu_svc(). Those builds can still drive a DSC
// through the legacy `$ dscu` netnode path (see crate::dsc), but not through
// this service, so the honest answer is NotSupported rather than an empty list.

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_images(
    idb: &Option<IDB>,
    _query: &DscImageQuery,
) -> Result<DscImageList, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Listing DSC images requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_image_deps(
    idb: &Option<IDB>,
    _query: &DscDepsQuery,
) -> Result<DscImageDeps, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Querying DSC image dependencies requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_find_symbols(
    idb: &Option<IDB>,
    _search: &DscSymbolSearch,
) -> Result<DscSymbolMatches, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Searching DSC symbols requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_find_strings(
    idb: &Option<IDB>,
    _search: &DscStringSearch,
) -> Result<DscStringMatches, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Searching DSC strings requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(not(feature = "ida-94"))]
pub fn handle_dsc_region_at(idb: &Option<IDB>, _ea: u64) -> Result<DscRegionQuery, ToolError> {
    idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    Err(ToolError::NotSupported(
        "Resolving a DSC region requires an IDA 9.4 build".to_string(),
    ))
}

#[cfg(all(test, feature = "ida-94"))]
mod tests {
    use super::dscu_unavailable_reason;

    #[test]
    fn a_saved_cache_database_is_told_which_file_to_reopen() {
        let reason = dscu_unavailable_reason("/caches/dyld_shared_cache_arm64e");
        assert!(
            reason.contains("/caches/dyld_shared_cache_arm64e"),
            "{reason}"
        );
        // The two things a reader has to take away: reopening the .i64 will
        // never work, and the database is not otherwise damaged.
        assert!(reason.contains("does not bring it back"), "{reason}");
        assert!(reason.contains("decompilation"), "{reason}");
    }

    #[test]
    fn a_database_from_something_else_is_not_blamed_on_a_lost_session() {
        let reason = dscu_unavailable_reason("/bin/ls");
        assert!(reason.contains("not created from"), "{reason}");
        assert!(reason.contains("/bin/ls"), "{reason}");
        // Nothing to reopen here, so the recovery advice must not appear.
        assert!(!reason.contains("open that cache again"), "{reason}");
    }

    #[test]
    fn an_unrecorded_input_file_still_produces_a_usable_sentence() {
        // IDA pads this field with NULs and can leave it empty; neither should
        // reach a caller as an empty pair of quotes.
        let reason = dscu_unavailable_reason("");
        assert!(reason.contains("unknown"), "{reason}");
        assert!(!reason.contains("()"), "{reason}");
    }
}
