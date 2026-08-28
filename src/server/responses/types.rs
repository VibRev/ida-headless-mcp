//! Local types, structs, stack frames, and type-mutation output types.

use crate::ida::types as worker;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;

/// One entry of the local type library.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalTypeInfo {
    /// Ordinal in the local type library — IDA's `get_numbered_type` key, not
    /// a position in this listing.
    ///
    /// Stable for the life of a database: auto-analysis *appends* types rather
    /// than renumbering them. Measured on a `/bin/cat` that grew from 5 local
    /// types to 26 while analysis ran, and a `/bin/bash` that grew from 5 to
    /// 87: every pre-existing ordinal still named the same type afterwards,
    /// and `declare_type` — with and without `replace` — did not move any.
    ///
    /// It is still an identifier the database owns rather than one you chose,
    /// and `local_types` lists typedefs and enums as well as structures, so an
    /// ordinal from here is not necessarily readable by `read_struct`. Pass
    /// `name` where a tool accepts one.
    pub ordinal: u32,
    /// Type name.
    pub name: String,
    /// C declaration IDA prints for the type.
    pub decl: String,
    /// Type flavor (`struct`, `union`, `enum`, `typedef`, ...).
    pub kind: String,
}

/// Paginated local type listing.
///
/// Pagination is positional within the filtered listing, not by `ordinal`.
/// Auto-analysis appends types, so a page taken while it runs can shift under
/// a later call — `analysis_coverage` is how you tell. The `ordinal` of a row
/// you already read does not shift; see [`LocalTypeInfo::ordinal`].
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalTypeListResult {
    /// Types in this page.
    pub types: Vec<LocalTypeInfo>,
    /// Total number of matches before pagination.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One structure or union, without its members.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructSummary {
    /// Ordinal in the local type library; see [`LocalTypeInfo::ordinal`].
    pub ordinal: u32,
    /// Structure name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// True for a union, false for a struct.
    pub is_union: bool,
    /// Number of members.
    pub member_count: u32,
}

/// Paginated structure listing.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructListResult {
    /// Structures in this page.
    pub structs: Vec<StructSummary>,
    /// Total number of matches before pagination.
    pub total: usize,
    /// Offset to pass on the next call; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One member of a structure or union.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructMemberInfo {
    /// Member name.
    pub name: String,
    /// C type of the member.
    pub type_name: String,
    /// Offset from the start of the structure, in bits.
    pub offset_bits: u64,
    /// Member width in bits.
    pub size_bits: u64,
    /// `offset_bits` rounded down to whole bytes.
    pub offset: u64,
    /// `size_bits` rounded up to whole bytes.
    pub size: u64,
    /// True when the member is a bitfield.
    pub is_bitfield: bool,
}

/// One structure or union with its members.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructInfo {
    /// Ordinal in the local type library.
    pub ordinal: u32,
    /// Structure name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// True for a union, false for a struct.
    pub is_union: bool,
    /// Number of entries in `members`.
    pub member_count: u32,
    /// Members in declaration order.
    pub members: Vec<StructMemberInfo>,
}

/// One member of a structure instance read out of the database.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructMemberValue {
    /// Member name.
    pub name: String,
    /// C type of the member.
    pub type_name: String,
    /// Offset from the start of the structure, in bits.
    pub offset_bits: u64,
    /// Member width in bits.
    pub size_bits: u64,
    /// `offset_bits` rounded down to whole bytes.
    pub offset: u64,
    /// `size_bits` rounded up to whole bytes.
    pub size: u64,
    /// True when the member is a bitfield.
    pub is_bitfield: bool,
    /// The member's bytes at this address, lowercase hex, no separators.
    pub bytes: String,
}

/// A structure instance read at an address.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StructReadResult {
    /// Address the instance was read from, hex-formatted.
    pub address: String,
    /// Ordinal of the structure type.
    pub ordinal: u32,
    /// Structure name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Members with their bytes at this address.
    pub members: Vec<StructMemberValue>,
}

/// One half-open sub-range of a stack frame.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrameRange {
    /// First frame offset in the range, hex-formatted.
    pub start: String,
    /// One past the last frame offset, hex-formatted.
    pub end: String,
}

/// One stack frame member.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrameMemberInfo {
    /// Variable name.
    pub name: String,
    /// C type of the variable.
    pub type_name: String,
    /// Offset within the frame, in bits.
    pub offset_bits: u64,
    /// Variable width in bits.
    pub size_bits: u64,
    /// `offset_bits` rounded down to whole bytes.
    pub offset: u64,
    /// `size_bits` rounded up to whole bytes.
    pub size: u64,
    /// True when the variable is a bitfield.
    pub is_bitfield: bool,
    /// Which frame region the variable lives in (`args`, `locals`, ...).
    pub part: String,
}

/// Layout of one function's stack frame.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrameInfo {
    /// Function entry address, hex-formatted.
    pub address: String,
    /// Total frame size in bytes.
    pub frame_size: u64,
    /// Bytes the callee pops off for the return address.
    pub ret_size: i32,
    /// Size of the local-variable area, in bytes.
    pub frsize: u64,
    /// Size of the saved-registers area, in bytes.
    pub frregs: u16,
    /// Size of the incoming-argument area, in bytes.
    pub argsize: u64,
    /// Frame pointer delta.
    pub fpd: u64,
    /// Frame offsets covering incoming arguments.
    pub args_range: FrameRange,
    /// Frame offsets covering the saved return address.
    pub retaddr_range: FrameRange,
    /// Frame offsets covering saved registers.
    pub savregs_range: FrameRange,
    /// Frame offsets covering local variables.
    pub locals_range: FrameRange,
    /// Number of entries in `members`.
    pub member_count: u32,
    /// Frame members in offset order.
    pub members: Vec<FrameMemberInfo>,
}

impl From<&worker::FrameRange> for FrameRange {
    fn from(range: &worker::FrameRange) -> Self {
        Self {
            start: range.start.clone(),
            end: range.end.clone(),
        }
    }
}

impl From<&worker::FrameMemberInfo> for FrameMemberInfo {
    fn from(member: &worker::FrameMemberInfo) -> Self {
        Self {
            name: member.name.clone(),
            type_name: member.type_name.clone(),
            offset_bits: member.offset_bits,
            size_bits: member.size_bits,
            offset: member.offset,
            size: member.size,
            is_bitfield: member.is_bitfield,
            part: member.part.clone(),
        }
    }
}

impl From<&worker::FrameInfo> for FrameInfo {
    fn from(frame: &worker::FrameInfo) -> Self {
        Self {
            address: frame.address.clone(),
            frame_size: frame.frame_size,
            ret_size: frame.ret_size,
            frsize: frame.frsize,
            frregs: frame.frregs,
            argsize: frame.argsize,
            fpd: frame.fpd,
            args_range: (&frame.args_range).into(),
            retaddr_range: (&frame.retaddr_range).into(),
            savregs_range: (&frame.savregs_range).into(),
            locals_range: (&frame.locals_range).into(),
            member_count: frame.member_count,
            members: frame.members.iter().map(FrameMemberInfo::from).collect(),
        }
    }
}

/// One address's struct read within a `read_struct` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadStructEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// The struct instance decoded at `address`; absent on failure.
    #[serde(rename = "struct", skip_serializing_if = "Option::is_none")]
    pub struct_value: Option<StructReadResult>,
    /// Why this address produced no value; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `read_struct` output.
///
/// No `analysis_coverage`: this reads bytes through a layout the caller named.
/// Analysis progress can make the *ordinal* of a type move — the local type
/// library grows as the analyzer loads type libraries — but that yields a
/// different struct, correctly decoded, not a partial one. Ordinal drift is a
/// real hazard in its own right; pass `name` rather than `ordinal` to avoid it.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadStructOutput {
    /// One entry per requested address, in request order.
    pub results: Vec<ReadStructEntry>,
}

/// `declare_type` output.
///
/// One declaration fills `code`/`name`/`decl`/`kind`/`replaced`;
/// `multi=true` parses a whole header and reports only `errors`.
///
/// A non-zero `code`, or a non-zero `errors`, means nothing was stored and the
/// result carries `isError: true` with this payload as the error detail.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclareTypeOutput {
    /// IDA's `parse_decl` status code; 0 means the declaration was accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// Name of the declared type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// IDA's echo of the declaration. In practice this is the declared type's
    /// name, not the C source that was parsed — use `local_types` or
    /// `struct_info` to read the stored definition back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decl: Option<String>,
    /// Type flavor (`struct`, `union`, `enum`, `typedef`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Echo of the `replace` argument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced: Option<bool>,
    /// Declarations that failed; present only for `multi=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<i32>,
}

/// Result of one stack-frame variable operation.
///
/// A non-zero `code` means the frame was *not* changed, and the result carries
/// `isError: true` — this payload is then the detail attached to the error, not
/// a success. `status` is kept because it was already on the wire, but a client
/// only needs to read `isError`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StackVarResult {
    /// Entry address of the owning function, hex-formatted.
    pub function: String,
    /// Variable name as IDA reports it after the operation.
    pub name: String,
    /// Frame offset of the variable.
    pub offset: i64,
    /// IDA status code; 0 means success. Non-zero arrives with `isError: true`.
    pub code: i32,
    /// `ok` when `code` is 0, `error` otherwise.
    pub status: String,
}

/// `apply_types` output.
///
/// Applying to an address fills `address`/`applied`/`source`; applying to a
/// stack variable (`stack_offset` or `stack_name`) answers with the
/// stack-frame shape instead.
///
/// `applied: false` (address arm) and a non-zero `code` (stack arm) both mean
/// the database was not changed, and both arrive with `isError: true` carrying
/// this payload as the error detail.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyTypesOutput {
    /// Address the type was applied to, hex-formatted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// True when IDA accepted the type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<bool>,
    /// Which argument supplied the type: `decl` or `named`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Entry address of the owning function, hex-formatted; stack arm only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Variable name after the operation; stack arm only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Frame offset of the variable; stack arm only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// IDA status code, 0 means success; stack arm only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// `ok` or `error`; stack arm only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// `infer_types` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuessTypeResult {
    /// Address the guess is about, hex-formatted.
    pub address: String,
    /// IDA's `guess_type` code: 0 failed, 1 trivial, 2 ok.
    pub code: i32,
    /// `failed`, `trivial`, `ok`, or `unknown` for a code IDA added later.
    pub status: String,
    /// The guessed C declaration; empty when nothing was guessed.
    pub decl: String,
    /// Type flavor of the guess.
    pub kind: String,
}
