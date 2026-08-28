//! Search handlers.

use crate::disasm::generate_disasm_line;
use crate::error::ToolError;
use crate::ida::handlers::parse_pattern;
use crate::ida::scan::{InsnScanRequest, PatternSet, ScanScope};
use idalib::IDB;
use serde_json::{json, Value};

fn strip_comment(line: &str) -> &str {
    line.split(';').next().unwrap_or(line)
}

fn split_disasm_line(line: &str) -> (String, String, String) {
    let trimmed = strip_comment(line).trim();
    if trimmed.is_empty() {
        return (String::new(), String::new(), String::new());
    }
    let mut parts = trimmed.splitn(2, |c: char| c.is_whitespace());
    let mnemonic = parts.next().unwrap_or("").trim().to_string();
    let operands = parts.next().unwrap_or("").trim().to_string();
    (mnemonic, operands, trimmed.to_string())
}

fn next_addr(db: &IDB, current: u64) -> Option<u64> {
    if let Some(insn) = db.insn_at(current) {
        let len = insn.len() as u64;
        if len == 0 {
            return None;
        }
        return Some(current.saturating_add(len));
    }
    db.next_head(current).filter(|next| *next > current)
}

pub fn handle_find_bytes(
    idb: &Option<IDB>,
    pattern: &str,
    max_results: usize,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let pat = parse_pattern(pattern)?;
    if pat.is_empty() {
        return Err(ToolError::IdaError("empty pattern".to_string()));
    }

    let mut matches = Vec::new();
    let pat_len = pat.len();
    let chunk_size: usize = 1024 * 1024;

    for (_id, seg) in db.segments() {
        let seg_start = seg.start_address();
        let seg_len = seg.len();
        let mut offset = 0usize;

        while offset < seg_len && matches.len() < max_results {
            let remaining = seg_len - offset;
            let read_len = remaining.min(chunk_size + pat_len.saturating_sub(1));
            let bytes = db.get_bytes(seg_start + offset as u64, read_len);
            if bytes.len() < pat_len {
                break;
            }

            for i in 0..=bytes.len() - pat_len {
                if matches.len() >= max_results {
                    break;
                }
                let mut ok = true;
                for (j, pb) in pat.iter().enumerate() {
                    if let Some(b) = pb
                        && bytes[i + j] != *b
                    {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    matches.push(format!("{:#x}", seg_start + offset as u64 + i as u64));
                }
            }

            if remaining <= chunk_size {
                break;
            }
            offset += chunk_size;
        }

        if matches.len() >= max_results {
            break;
        }
    }

    Ok(json!({
        "pattern": pattern,
        "matches": matches,
        "count": matches.len()
    }))
}

/// Does `addr` sit in an executable segment?
///
/// `code_only` filters on segment permissions rather than on "is there a
/// function here": a match inside an unanalysed run of bytes in `.text` is
/// still code the caller asked about.
fn in_executable_segment(db: &IDB, addr: u64) -> bool {
    db.segment_at(addr)
        .is_some_and(|seg| seg.permissions().is_executable())
}

/// Text matches inside one `[start, end)` range.
///
/// Seeds IDA's search at `start` instead of filtering a from-zero iterator:
/// on a large database the skipped prefix is the whole cost of the call.
fn text_matches_in<'a>(
    db: &'a IDB,
    text: &'a str,
    start: u64,
    end: u64,
) -> impl Iterator<Item = u64> + 'a {
    let mut cursor = Some(start);
    std::iter::from_fn(move || {
        let found = db.find_text(cursor?, text)?;
        if found >= end {
            return None;
        }
        cursor = db.find_defined(found);
        Some(found)
    })
}

/// Immediate-operand matches inside one `[start, end)` range.
fn imm_matches_in(db: &IDB, imm: u32, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
    let mut cursor = start;
    std::iter::from_fn(move || {
        let found = db.find_imm(cursor, imm)?;
        if found >= end {
            return None;
        }
        cursor = found.saturating_add(1);
        Some(found)
    })
}

pub fn handle_search_text(
    idb: &Option<IDB>,
    text: &str,
    max_results: usize,
    scope: &ScanScope,
    code_only: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let matches = scope
        .ranges(db)?
        .into_iter()
        .flat_map(|(start, end)| text_matches_in(db, text, start, end))
        .filter(|addr| !code_only || in_executable_segment(db, *addr))
        .take(max_results)
        .map(|addr| format!("{addr:#x}"))
        .collect::<Vec<_>>();

    Ok(json!({
        "matches": matches,
        "count": matches.len(),
        "scope": scope.describe(),
        "code_only": code_only
    }))
}

pub fn handle_search_imm(
    idb: &Option<IDB>,
    imm: u64,
    max_results: usize,
    scope: &ScanScope,
    code_only: bool,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let imm32 = imm as u32;
    let matches = scope
        .ranges(db)?
        .into_iter()
        .flat_map(|(start, end)| imm_matches_in(db, imm32, start, end))
        .filter(|addr| !code_only || in_executable_segment(db, *addr))
        .take(max_results)
        .map(|addr| format!("{addr:#x}"))
        .collect::<Vec<_>>();

    Ok(json!({
        "matches": matches,
        "count": matches.len(),
        "scope": scope.describe(),
        "code_only": code_only
    }))
}

/// Walk forward from `addr`, requiring patterns `1..` to match consecutive
/// instructions. Returns the matched addresses, or `None` if the run breaks.
///
/// Split out of the scan loop because a sequence match reads ahead past the
/// cursor: the walk that finds candidates and the walk that confirms them are
/// two different traversals over the same instruction stream.
fn match_sequence(db: &IDB, matcher: &PatternSet, start: u64, range_end: u64) -> Option<Vec<u64>> {
    let mut addrs = vec![start];
    let mut current = start;

    for index in 1..matcher.pattern_count() {
        let next = next_addr(db, current).filter(|next| *next < range_end)?;
        let line = generate_disasm_line(db, next)?;
        let (mnemonic, _operands, clean) = split_disasm_line(&line);
        if mnemonic.is_empty() || !matcher.matches_insn(index, &mnemonic, &clean) {
            return None;
        }
        addrs.push(next);
        current = next;
    }

    Some(addrs)
}

pub fn handle_find_insns(idb: &Option<IDB>, scan: &InsnScanRequest) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let matcher = scan.matcher()?;
    let mut heads = scan.scope.heads(db, scan.max_scan)?;
    let mut matches = Vec::new();
    // Set only when the walk was cut short, not when it happened to end on the
    // limit: `matches.len() == max_results` with the heads exhausted is a
    // complete answer, and reporting it as truncated would send a caller
    // looking for matches that are not there.
    let mut truncated = false;

    for addr in heads.by_ref() {
        if matches.len() >= scan.max_results {
            truncated = true;
            break;
        }
        let Some(line) = generate_disasm_line(db, addr) else {
            continue;
        };
        let (mnemonic, _operands, clean_line) = split_disasm_line(&line);
        if mnemonic.is_empty() || !matcher.matches_insn(0, &mnemonic, &clean_line) {
            continue;
        }

        if matcher.pattern_count() == 1 {
            matches.push(json!({
                "address": format!("{:#x}", addr),
                "mnemonic": mnemonic,
                "line": clean_line
            }));
            continue;
        }

        // A sequence may not run past the range the head walk is confined to.
        let range_end = scan.scope.range_end_for(db, addr)?;
        if let Some(seq) = match_sequence(db, &matcher, addr, range_end) {
            matches.push(json!({
                "address": format!("{:#x}", addr),
                "mnemonic": mnemonic,
                "line": clean_line,
                "sequence": seq.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>()
            }));
        }
    }

    Ok(json!({
        "patterns": scan.patterns,
        "case_insensitive": scan.case_insensitive,
        "regex": scan.regex,
        "scope": scan.scope.describe(),
        "scanned": heads.scanned(),
        "scan_truncated": heads.hit_scan_limit(),
        "matches": matches,
        "count": matches.len(),
        "truncated": truncated
    }))
}

pub fn handle_find_insn_operands(
    idb: &Option<IDB>,
    scan: &InsnScanRequest,
) -> Result<Value, ToolError> {
    let db = idb.as_ref().ok_or(ToolError::NoDatabaseOpen)?;
    let matcher = scan.matcher()?;
    let mut heads = scan.scope.heads(db, scan.max_scan)?;
    let mut matches = Vec::new();
    // Set only when the walk was cut short, not when it happened to end on the
    // limit: `matches.len() == max_results` with the heads exhausted is a
    // complete answer, and reporting it as truncated would send a caller
    // looking for matches that are not there.
    let mut truncated = false;

    for addr in heads.by_ref() {
        if matches.len() >= scan.max_results {
            truncated = true;
            break;
        }
        let Some(line) = generate_disasm_line(db, addr) else {
            continue;
        };
        let (mnemonic, operands, clean_line) = split_disasm_line(&line);
        if mnemonic.is_empty() || !matcher.matches_any(&operands) {
            continue;
        }
        matches.push(json!({
            "address": format!("{:#x}", addr),
            "mnemonic": mnemonic,
            "operands": operands,
            "line": clean_line
        }));
    }

    Ok(json!({
        "patterns": scan.patterns,
        "case_insensitive": scan.case_insensitive,
        "regex": scan.regex,
        "scope": scan.scope.describe(),
        "scanned": heads.scanned(),
        "scan_truncated": heads.hit_scan_limit(),
        "matches": matches,
        "count": matches.len(),
        "truncated": truncated
    }))
}
