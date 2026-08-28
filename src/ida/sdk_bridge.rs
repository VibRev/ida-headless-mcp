//! Narrow safe wrappers around IDA SDK operations not yet exposed by `idalib`.

use std::ffi::CString;

unsafe extern "C" {
    fn ida_mcp_save_database(path: *const libc::c_char, compress: bool) -> bool;
    fn ida_mcp_add_func(start: u64, end: u64) -> bool;
    fn ida_mcp_create_insn(address: u64) -> libc::c_int;
    fn ida_mcp_undefine(address: u64, size: u64) -> bool;
    fn ida_mcp_reanalyze(start: u64, end: u64) -> bool;
    fn ida_mcp_make_data(
        address: u64,
        declaration: *const libc::c_char,
        delete_existing: bool,
        out_size: *mut u64,
    ) -> bool;
    fn ida_mcp_mark_cfunc_dirty(address: u64) -> bool;
    fn ida_mcp_init_hexrays() -> bool;
    fn ida_mcp_enum_upsert_member(
        enum_name: *const libc::c_char,
        member_name: *const libc::c_char,
        value: u64,
        bitfield: bool,
        created_enum: *mut bool,
        ordinal: *mut u32,
    ) -> libc::c_int;
    fn ida_mcp_rename_local(
        function_address: u64,
        old_name: *const libc::c_char,
        new_name: *const libc::c_char,
    ) -> bool;
    fn ida_mcp_rename_stack(
        function_address: u64,
        old_name: *const libc::c_char,
        new_name: *const libc::c_char,
    ) -> bool;
    fn ida_mcp_get_applied_udt_name(
        address: u64,
        buffer: *mut libc::c_char,
        buffer_size: usize,
    ) -> bool;
    fn ida_mcp_operand_mask(address: u64, size: u64, mask: *mut u8) -> bool;
    fn ida_mcp_set_operand_type(
        address: u64,
        operand: libc::c_int,
        kind: *const libc::c_char,
        target: u64,
        struct_name: *const libc::c_char,
        delta: i64,
    ) -> bool;
}

pub fn save_database(path: Option<&str>, compress: bool) -> Result<bool, String> {
    let path = path
        .filter(|path| !path.is_empty())
        .map(CString::new)
        .transpose()
        .map_err(|error| format!("invalid database path: {error}"))?;
    Ok(unsafe {
        ida_mcp_save_database(
            path.as_ref().map_or(std::ptr::null(), |path| path.as_ptr()),
            compress,
        )
    })
}

pub fn add_func(start: u64, end: Option<u64>) -> bool {
    unsafe { ida_mcp_add_func(start, end.unwrap_or(0)) }
}

pub fn create_insn(address: u64) -> usize {
    usize::try_from(unsafe { ida_mcp_create_insn(address) }).unwrap_or(0)
}

pub fn undefine(address: u64, size: u64) -> bool {
    unsafe { ida_mcp_undefine(address, size) }
}

pub fn reanalyze(start: u64, end: u64) -> bool {
    unsafe { ida_mcp_reanalyze(start, end) }
}

pub fn make_data(
    address: u64,
    declaration: &str,
    delete_existing: bool,
) -> Result<Option<u64>, String> {
    let declaration =
        CString::new(declaration).map_err(|error| format!("invalid declaration: {error}"))?;
    let mut size = 0;
    let success =
        unsafe { ida_mcp_make_data(address, declaration.as_ptr(), delete_existing, &mut size) };
    Ok(success.then_some(size))
}

pub fn mark_cfunc_dirty(address: u64) -> bool {
    unsafe { ida_mcp_mark_cfunc_dirty(address) }
}

pub fn init_hexrays() -> bool {
    unsafe { ida_mcp_init_hexrays() }
}

#[derive(Debug, Clone, Copy)]
pub enum EnumMemberUpsert {
    Created { enum_created: bool, ordinal: u32 },
    Skipped { ordinal: u32 },
}

pub fn enum_upsert_member(
    enum_name: &str,
    member_name: &str,
    value: u64,
    bitfield: bool,
) -> Result<EnumMemberUpsert, String> {
    let enum_name =
        CString::new(enum_name).map_err(|error| format!("invalid enum name: {error}"))?;
    let member_name =
        CString::new(member_name).map_err(|error| format!("invalid enum member name: {error}"))?;
    let mut enum_created = false;
    let mut ordinal = 0;
    let status = unsafe {
        ida_mcp_enum_upsert_member(
            enum_name.as_ptr(),
            member_name.as_ptr(),
            value,
            bitfield,
            &mut enum_created,
            &mut ordinal,
        )
    };
    match status {
        1 => Ok(EnumMemberUpsert::Created {
            enum_created,
            ordinal,
        }),
        2 => Ok(EnumMemberUpsert::Skipped { ordinal }),
        -6 => Err(format!(
            "Enum value conflict: {value} is already assigned to another member"
        )),
        -9 => Err("Enum bitfield setting does not match the existing enum".to_string()),
        -21 => Err(format!(
            "Enum member name conflict: {member_name:?} already has another value"
        )),
        code => Err(format!("IDA enum update failed with type error {code}")),
    }
}

pub fn rename_variable(
    function_address: u64,
    old_name: &str,
    new_name: &str,
    stack: bool,
) -> Result<bool, String> {
    let old_name =
        CString::new(old_name).map_err(|error| format!("invalid old variable name: {error}"))?;
    let new_name =
        CString::new(new_name).map_err(|error| format!("invalid new variable name: {error}"))?;
    Ok(unsafe {
        if stack {
            ida_mcp_rename_stack(function_address, old_name.as_ptr(), new_name.as_ptr())
        } else {
            ida_mcp_rename_local(function_address, old_name.as_ptr(), new_name.as_ptr())
        }
    })
}

pub fn applied_udt_name(address: u64) -> Option<String> {
    let mut buffer = vec![0u8; 4096];
    if !unsafe {
        ida_mcp_get_applied_udt_name(
            address,
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    } {
        return None;
    }
    let nul = buffer.iter().position(|byte| *byte == 0)?;
    String::from_utf8(buffer[..nul].to_vec()).ok()
}

pub fn operand_mask(address: u64, size: usize) -> Option<Vec<bool>> {
    let size_u64 = u64::try_from(size).ok()?;
    let mut mask = vec![0u8; size];
    if !unsafe { ida_mcp_operand_mask(address, size_u64, mask.as_mut_ptr()) } {
        return None;
    }
    Some(mask.into_iter().map(|byte| byte != 0).collect())
}

pub fn set_operand_type(
    address: u64,
    operand: i32,
    kind: &str,
    target: Option<u64>,
    struct_name: Option<&str>,
    delta: i64,
) -> Result<bool, String> {
    let kind = CString::new(kind).map_err(|error| format!("invalid operand type kind: {error}"))?;
    let struct_name = struct_name
        .map(CString::new)
        .transpose()
        .map_err(|error| format!("invalid structure name: {error}"))?;
    Ok(unsafe {
        ida_mcp_set_operand_type(
            address,
            operand,
            kind.as_ptr(),
            target.unwrap_or(0),
            struct_name
                .as_ref()
                .map_or(std::ptr::null(), |name| name.as_ptr()),
            delta,
        )
    })
}
