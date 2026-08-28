//! Scope and pattern primitives shared by the instruction scanners.
//!
//! `find_insns` and `find_insn_operands` take a scope rather than walking every
//! segment of the database. Without one, looking at a single function means
//! scanning the whole binary and filtering the answer client-side — on a large
//! target, the difference between reading a few hundred instructions and a few
//! million.
//!
//! Scope selection, the head walk, and the matching rule live here so the two
//! scanners cannot drift apart the way copied segment loops do.

use crate::error::ToolError;
use idalib::IDB;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Instructions walked before a scan gives up when the caller named no bound.
///
/// A scopeless scan over a stripped 100 MB binary would otherwise sit in the
/// worker until the tool timeout fires and the caller gets nothing at all. A
/// truncated answer that says it is truncated beats a timeout.
pub const DEFAULT_MAX_SCAN: usize = 500_000;

/// The mutually exclusive scope fields as they arrive from a tool request.
#[derive(Debug, Default, Clone)]
pub struct ScopeSpec {
    pub function: Option<u64>,
    pub segment: Option<String>,
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// The address ranges an instruction scan walks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum ScanScope {
    /// Every segment, in database order.
    Database,
    /// The chunk range of the function containing this address.
    Function(u64),
    /// One segment, by name.
    Segment(String),
    /// A half-open `[start, end)` range.
    Range { start: u64, end: u64 },
}

impl ScanScope {
    /// Pick the scope named by a request's scope fields.
    ///
    /// Naming two scopes is an error rather than a silent precedence rule:
    /// letting one quietly win answers a question the caller did not ask.
    /// `resolve_udt` rejects an ordinal/name pair for the same reason.
    pub fn select(spec: ScopeSpec) -> Result<Self, ToolError> {
        let ScopeSpec {
            function,
            segment,
            start,
            end,
        } = spec;
        let range_named = start.is_some() || end.is_some();
        let named = usize::from(function.is_some())
            + usize::from(segment.is_some())
            + usize::from(range_named);
        if named > 1 {
            return Err(ToolError::InvalidParams(
                "name at most one scope: 'function', 'segment', or 'start'/'end'".to_string(),
            ));
        }

        match (function, segment, start, end) {
            (Some(addr), _, _, _) => Ok(Self::Function(addr)),
            (_, Some(name), _, _) => Ok(Self::Segment(name)),
            (_, _, Some(start), Some(end)) if end > start => Ok(Self::Range { start, end }),
            (_, _, Some(start), Some(end)) => Err(ToolError::InvalidParams(format!(
                "scope 'end' ({end:#x}) must be greater than 'start' ({start:#x})"
            ))),
            (_, _, Some(_), None) => Err(ToolError::InvalidParams(
                "scope 'start' needs a matching 'end'".to_string(),
            )),
            (_, _, None, Some(_)) => Err(ToolError::InvalidParams(
                "scope 'end' needs a matching 'start'".to_string(),
            )),
            (None, None, None, None) => Ok(Self::Database),
        }
    }

    /// Resolve to concrete `[start, end)` ranges against an open database.
    ///
    /// Public because the text and immediate searches reuse the scope without
    /// reusing the instruction walk: they hand the range to IDA's own search
    /// rather than decoding every head themselves.
    pub fn ranges(&self, db: &IDB) -> Result<Vec<(u64, u64)>, ToolError> {
        match self {
            Self::Database => Ok(db
                .segments()
                .map(|(_id, seg)| (seg.start_address(), seg.end_address()))
                .collect()),
            Self::Function(addr) => {
                let func = db
                    .function_at(*addr)
                    .ok_or(ToolError::FunctionNotFound(*addr))?;
                Ok(vec![(func.start_address(), func.end_address())])
            }
            Self::Segment(name) => {
                let seg = db.segment_by_name(name).ok_or_else(|| {
                    ToolError::InvalidParams(format!("no segment named '{name}'"))
                })?;
                Ok(vec![(seg.start_address(), seg.end_address())])
            }
            Self::Range { start, end } => Ok(vec![(*start, *end)]),
        }
    }

    /// Walk instruction heads across this scope, stopping after `max_scan`.
    pub fn heads<'a>(&self, db: &'a IDB, max_scan: usize) -> Result<InsnHeads<'a>, ToolError> {
        Ok(InsnHeads {
            db,
            ranges: self.ranges(db)?.into_iter().collect(),
            current: None,
            budget: max_scan,
            scanned: 0,
            exhausted_budget: false,
        })
    }

    /// The end of the range containing `addr`, so a sequence match started at
    /// the last instruction of a range cannot silently run into the next one.
    pub fn range_end_for(&self, db: &IDB, addr: u64) -> Result<u64, ToolError> {
        match self {
            Self::Database | Self::Segment(_) => db
                .segment_at(addr)
                .map(|seg| seg.end_address())
                .ok_or(ToolError::AddressOutOfRange(addr)),
            Self::Function(func_addr) => db
                .function_at(*func_addr)
                .map(|func| func.end_address())
                .ok_or(ToolError::FunctionNotFound(*func_addr)),
            Self::Range { end, .. } => Ok(*end),
        }
    }

    /// The mutually exclusive tool-argument fields this scope was selected
    /// from, for backends that forward over the public tool surface.
    pub fn to_tool_fields(&self) -> serde_json::Value {
        match self {
            Self::Database => serde_json::json!({}),
            Self::Function(addr) => serde_json::json!({ "function": format!("{addr:#x}") }),
            Self::Segment(name) => serde_json::json!({ "segment": name }),
            Self::Range { start, end } => serde_json::json!({
                "start": format!("{start:#x}"),
                "end": format!("{end:#x}"),
            }),
        }
    }

    /// Human-readable form for the `scope` field of a scan answer.
    pub fn describe(&self) -> String {
        match self {
            Self::Database => "database".to_string(),
            Self::Function(addr) => format!("function:{addr:#x}"),
            Self::Segment(name) => format!("segment:{name}"),
            Self::Range { start, end } => format!("range:{start:#x}-{end:#x}"),
        }
    }
}

/// Instruction heads within a [`ScanScope`], bounded by a scan budget.
///
/// Yields addresses rather than decoded instructions: the two scanners want
/// different things out of each head, and decoding twice is cheaper than
/// carrying a decoded instruction neither of them may use.
pub struct InsnHeads<'a> {
    db: &'a IDB,
    ranges: std::collections::VecDeque<(u64, u64)>,
    current: Option<(u64, u64)>,
    budget: usize,
    scanned: usize,
    exhausted_budget: bool,
}

impl InsnHeads<'_> {
    /// Instructions visited so far.
    pub fn scanned(&self) -> usize {
        self.scanned
    }

    /// Did the walk stop because it ran out of budget rather than addresses?
    ///
    /// The caller reports this so a partial scan cannot be read as a complete
    /// one — the same reason `search` reports `total_is_lower_bound`.
    pub fn hit_scan_limit(&self) -> bool {
        self.exhausted_budget
    }

    /// The next defined head at or after `addr`, within `end`.
    fn step(&self, addr: u64, end: u64) -> Option<u64> {
        let next = match self.db.insn_at(addr) {
            Some(insn) if !insn.is_empty() => addr.saturating_add(insn.len() as u64),
            _ => self.db.next_head(addr).filter(|next| *next > addr)?,
        };
        (next > addr && next < end).then_some(next)
    }
}

impl Iterator for InsnHeads<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        loop {
            if self.scanned >= self.budget {
                self.exhausted_budget = true;
                return None;
            }

            match self.current {
                Some((addr, end)) => {
                    self.current = self.step(addr, end).map(|next| (next, end));
                    self.scanned += 1;
                    return Some(addr);
                }
                None => {
                    let (start, end) = self.ranges.pop_front()?;
                    if start < end {
                        self.current = Some((start, end));
                    }
                }
            }
        }
    }
}

/// How scan patterns are compared against disassembly text.
///
/// Literal matching is the historical behaviour and stays the default: a bare
/// `mov` should not have to be escaped. Regex is opt-in per call.
pub enum PatternSet {
    /// Substring match, optionally case-folded.
    Literal {
        patterns: Vec<String>,
        case_insensitive: bool,
    },
    /// Compiled regular expressions, one per requested pattern.
    Regex(Vec<Regex>),
}

impl PatternSet {
    /// Compile the request's patterns, rejecting an empty set.
    pub fn compile(
        patterns: &[String],
        case_insensitive: bool,
        regex: bool,
    ) -> Result<Self, ToolError> {
        if patterns.is_empty() {
            return Err(ToolError::InvalidParams("empty patterns".to_string()));
        }

        if !regex {
            let patterns = if case_insensitive {
                patterns.iter().map(|p| p.to_ascii_lowercase()).collect()
            } else {
                patterns.to_vec()
            };
            return Ok(Self::Literal {
                patterns,
                case_insensitive,
            });
        }

        patterns
            .iter()
            .map(|pattern| {
                regex::RegexBuilder::new(pattern)
                    .case_insensitive(case_insensitive)
                    .build()
                    .map_err(|error| {
                        ToolError::InvalidParams(format!("invalid regex '{pattern}': {error}"))
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self::Regex)
    }

    /// How many patterns this set holds; the scanners use it for sequences.
    ///
    /// Not `len`: [`Self::compile`] rejects an empty set, so this type has no
    /// empty state and must not offer the collection contract that name implies.
    pub fn pattern_count(&self) -> usize {
        match self {
            Self::Literal { patterns, .. } => patterns.len(),
            Self::Regex(regexes) => regexes.len(),
        }
    }

    /// Does pattern `index` match this mnemonic / full-line pair?
    ///
    /// A literal pattern carrying a space or comma is aimed at the whole line
    /// (`"mov rax, rbx"`); a bare word is aimed at the mnemonic. A regex is
    /// always matched against the full line, because anchoring is the caller's
    /// job once they have asked for a regex.
    pub fn matches_insn(&self, index: usize, mnemonic: &str, line: &str) -> bool {
        match self {
            Self::Literal {
                patterns,
                case_insensitive,
            } => {
                let Some(pattern) = patterns.get(index) else {
                    return false;
                };
                let whole_line = pattern.contains(' ') || pattern.contains(',');
                let haystack = if whole_line { line } else { mnemonic };
                if *case_insensitive {
                    haystack.to_ascii_lowercase().contains(pattern)
                } else {
                    haystack.contains(pattern)
                }
            }
            Self::Regex(regexes) => regexes.get(index).is_some_and(|re| re.is_match(line)),
        }
    }

    /// Does any pattern match this text? Used by the operand scanner, which has
    /// no sequence semantics.
    pub fn matches_any(&self, text: &str) -> bool {
        match self {
            Self::Literal {
                patterns,
                case_insensitive,
            } => {
                let haystack = if *case_insensitive {
                    text.to_ascii_lowercase()
                } else {
                    text.to_string()
                };
                patterns.iter().any(|pattern| haystack.contains(pattern))
            }
            Self::Regex(regexes) => regexes.iter().any(|re| re.is_match(text)),
        }
    }
}

/// Splice a scope's tool fields into an argument object already under
/// construction. A no-op for [`ScanScope::Database`], which names no field.
pub fn merge_tool_fields(args: &mut serde_json::Value, scope: &ScanScope) {
    let fields = scope.to_tool_fields();
    if let (Some(args), Some(fields)) = (args.as_object_mut(), fields.as_object()) {
        args.extend(fields.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
}

/// One bounded instruction scan, as it reaches the worker.
///
/// `find_insns` and `find_insn_operands` take the same inputs and differ only
/// in what they compare, so they share the request rather than keeping two
/// parameter lists in step by hand.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InsnScanRequest {
    pub patterns: Vec<String>,
    pub max_results: usize,
    pub case_insensitive: bool,
    pub regex: bool,
    pub scope: ScanScope,
    pub max_scan: usize,
}

impl InsnScanRequest {
    /// Compile this request's patterns. Fails on an invalid regex, before any
    /// instruction is decoded.
    pub fn matcher(&self) -> Result<PatternSet, ToolError> {
        PatternSet::compile(&self.patterns, self.case_insensitive, self.regex)
    }

    /// Re-flatten into the tool arguments a pooled worker expects.
    ///
    /// The HTTP pool forwards calls over the public tool surface rather than
    /// over this struct, so the scope enum has to go back to the mutually
    /// exclusive fields it was selected from.
    pub fn to_tool_args(&self, timeout_secs: Option<u64>) -> serde_json::Value {
        let mut args = serde_json::json!({
            "patterns": self.patterns,
            "limit": self.max_results,
            "case_insensitive": self.case_insensitive,
            "regex": self.regex,
            "max_scan": self.max_scan,
            "timeout_secs": timeout_secs,
        });
        merge_tool_fields(&mut args, &self.scope);
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_select_defaults_to_the_whole_database() {
        let scope = ScanScope::select(ScopeSpec::default()).expect("an empty spec is valid");
        assert_eq!(scope, ScanScope::Database);
    }

    #[test]
    fn scope_select_rejects_two_scopes() {
        let spec = ScopeSpec {
            function: Some(0x1000),
            segment: Some(".text".to_string()),
            ..Default::default()
        };
        assert!(ScanScope::select(spec).is_err());
    }

    #[test]
    fn scope_select_rejects_a_half_named_range() {
        let spec = ScopeSpec {
            start: Some(0x1000),
            ..Default::default()
        };
        assert!(ScanScope::select(spec).is_err());
    }

    #[test]
    fn scope_select_rejects_an_inverted_range() {
        let spec = ScopeSpec {
            start: Some(0x2000),
            end: Some(0x1000),
            ..Default::default()
        };
        assert!(ScanScope::select(spec).is_err());
    }

    #[test]
    fn literal_patterns_target_the_mnemonic_until_they_carry_a_separator() {
        let bare = PatternSet::compile(&["mov".to_string()], false, false)
            .expect("a literal pattern set compiles");
        assert!(bare.matches_insn(0, "mov", "mov rax, rbx"));
        assert!(!bare.matches_insn(0, "call", "call mov_helper"));

        let phrase = PatternSet::compile(&["rax, rbx".to_string()], false, false)
            .expect("a literal pattern set compiles");
        assert!(phrase.matches_insn(0, "mov", "mov rax, rbx"));
    }

    #[test]
    fn regex_patterns_match_the_whole_line() {
        let set = PatternSet::compile(&[r"^mov\s+r[a-z]x".to_string()], false, true)
            .expect("a valid regex compiles");
        assert!(set.matches_insn(0, "mov", "mov rax, rbx"));
        assert!(!set.matches_insn(0, "mov", "mov [rsp+8], rbx"));
    }

    #[test]
    fn an_invalid_regex_is_a_parameter_error() {
        let error = PatternSet::compile(&["(unclosed".to_string()], false, true);
        assert!(error.is_err());
    }

    #[test]
    fn case_insensitive_regex_folds_both_sides() {
        let set =
            PatternSet::compile(&["MOV".to_string()], true, true).expect("a valid regex compiles");
        assert!(set.matches_insn(0, "mov", "mov rax, rbx"));
    }
}
