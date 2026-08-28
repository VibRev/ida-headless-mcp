//! Signature generation: grow a byte pattern until it identifies one place.

use crate::error::ToolError;
use crate::ida::sdk_bridge;
use crate::ida::signature::{Signature, SignatureFormat};
use idalib::IDB;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// One signature request, as it reaches the worker.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignatureRequest {
    /// Where the pattern starts.
    pub address: u64,
    /// When set, cover exactly `[address, end)` instead of growing until
    /// unique. Uniqueness is still reported, just not searched for.
    pub end: Option<u64>,
    /// Replace operand bytes with wildcards so the pattern survives
    /// relocation and recompilation.
    pub wildcard_operands: bool,
    /// Give up once the pattern reaches this many bytes.
    pub max_length: usize,
    pub format: SignatureFormat,
}

/// Matches to look for before concluding a pattern is not unique.
///
/// Two is enough: the pattern always matches the address it came from, so a
/// second match is what makes it ambiguous. Counting further would be work
/// whose answer changes nothing.
const UNIQUENESS_STOP: usize = 2;

/// Count matches of a wildcard pattern across the database, stopping early.
///
/// Reads one segment at a time in chunks that overlap by `pattern.len() - 1`
/// so a match straddling a chunk boundary is not lost.
fn count_matches(db: &IDB, pattern: &[Option<u8>], stop_at: usize) -> usize {
    const CHUNK: usize = 1024 * 1024;
    let pat_len = pattern.len();
    if pat_len == 0 {
        return 0;
    }

    let mut found = 0usize;
    for (_id, seg) in db.segments() {
        let seg_start = seg.start_address();
        let seg_len = seg.len();
        let mut offset = 0usize;

        while offset < seg_len {
            let remaining = seg_len - offset;
            let read_len = remaining.min(CHUNK + pat_len.saturating_sub(1));
            let bytes = db.get_bytes(seg_start + offset as u64, read_len);
            if bytes.len() < pat_len {
                break;
            }

            for window in bytes.windows(pat_len) {
                let hit = pattern
                    .iter()
                    .zip(window)
                    .all(|(want, got)| want.is_none_or(|want| want == *got));
                if hit {
                    found += 1;
                    if found >= stop_at {
                        return found;
                    }
                }
            }

            if remaining <= CHUNK {
                break;
            }
            offset += CHUNK;
        }
    }
    found
}

/// The length of the instruction at `addr`, or `None` if nothing decodes.
fn insn_len(db: &IDB, addr: u64) -> Option<usize> {
    db.insn_at(addr)
        .map(|insn| insn.len())
        .filter(|len| *len > 0)
}

/// Append one instruction's bytes to `sig`, wildcarding operands if asked.
fn append_instruction(
    db: &IDB,
    sig: &mut Signature,
    addr: u64,
    len: usize,
    wildcard_operands: bool,
) -> Result<(), ToolError> {
    let bytes = db.get_bytes(addr, len);
    if bytes.len() != len {
        return Err(ToolError::AddressOutOfRange(addr));
    }

    // An absent mask means the SDK could not describe this instruction's
    // operands. Treating every byte as exact is the safe reading: the
    // signature stays correct, it just does not survive relocation.
    let mask = if wildcard_operands {
        sdk_bridge::operand_mask(addr, len).unwrap_or_else(|| vec![true; len])
    } else {
        vec![true; len]
    };

    for (index, byte) in bytes.iter().enumerate() {
        let exact = mask.get(index).copied().unwrap_or(true);
        sig.push(*byte, !exact);
    }
    Ok(())
}

pub fn handle_make_signature(
    idb: &Option<IDB>,
    request: &SignatureRequest,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    if request.max_length == 0 {
        return Err(ToolError::InvalidParams(
            "max_length must be at least 1".to_string(),
        ));
    }
    if let Some(end) = request.end
        && end <= request.address
    {
        return Err(ToolError::InvalidParams(format!(
            "end ({end:#x}) must be greater than address ({:#x})",
            request.address
        )));
    }

    // x86 decodes almost any byte run into *something*, so `insn_at` succeeds
    // on data and hands back a garbage instruction length. Without this check
    // a GOT entry produces a confident-looking signature over a "decode" that
    // means nothing. Segment permissions are the honest gate.
    if !db
        .segment_at(request.address)
        .is_some_and(|seg| seg.permissions().is_executable())
    {
        return Err(ToolError::InvalidParams(format!(
            "{:#x} is not in an executable segment; signatures are generated over code",
            request.address
        )));
    }

    let mut sig = Signature::new();
    let mut cursor = request.address;
    let mut instructions = 0usize;
    let mut unique = false;

    loop {
        let Some(len) = insn_len(db, cursor) else {
            // No decoded instruction here. If nothing has been collected the
            // address is not code at all; otherwise the run simply ended.
            if sig.is_empty() {
                return Err(ToolError::IdaError(format!(
                    "no instruction decodes at {cursor:#x}; \
                     signatures are generated over code"
                )));
            }
            break;
        };

        append_instruction(db, &mut sig, cursor, len, request.wildcard_operands)?;
        instructions += 1;
        cursor = cursor.saturating_add(len as u64);

        match request.end {
            // Fixed-range mode: keep going until the range is covered.
            Some(end) => {
                if cursor >= end {
                    break;
                }
            }
            // Search mode: a pattern ending in wildcards is no stronger than
            // the same pattern without them, so test the trimmed form.
            None => {
                let mut candidate = sig.clone();
                candidate.trim_trailing_wildcards();
                if !candidate.is_empty()
                    && count_matches(db, &candidate.to_scan_pattern(), UNIQUENESS_STOP) == 1
                {
                    sig = candidate;
                    unique = true;
                    break;
                }
            }
        }

        if sig.len() >= request.max_length {
            break;
        }
    }

    if request.end.is_some() || !unique {
        sig.trim_trailing_wildcards();
        if !sig.is_empty() {
            unique = count_matches(db, &sig.to_scan_pattern(), UNIQUENESS_STOP) == 1;
        }
    }

    if sig.is_empty() {
        return Err(ToolError::IdaError(format!(
            "no signature could be built at {:#x}: every byte was an operand",
            request.address
        )));
    }

    Ok(json!({
        "address": format!("{:#x}", request.address),
        "signature": sig.render(request.format),
        "format": request.format,
        "length": sig.len(),
        "instructions": instructions,
        "unique": unique,
        "wildcard_operands": request.wildcard_operands,
        // A non-unique answer is still returned: it is the best pattern found
        // within max_length, and the caller may want to widen it by hand.
        "truncated": !unique && request.end.is_none() && sig.len() >= request.max_length,
    }))
}
