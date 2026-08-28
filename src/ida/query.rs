//! Filtering and ordering primitives for the listing tools.
//!
//! Every listing — functions, globals, imports, exports, strings, types —
//! filters and orders on this side. A listing that offers only a case-folded
//! substring turns "functions bigger than 0x100, largest first" into paging the
//! whole listing into the caller's context and sorting it there, which is the
//! expensive half of the answer done in the wrong place.
//!
//! These types are shared so a filter means the same thing in every listing.

use crate::error::ToolError;
use regex::{Regex, RegexBuilder};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// How a listing decides whether a name is in the answer.
///
/// `filter` keeps its historical case-folded-substring meaning; `regex` is the
/// opt-in precise form. Naming both is an error rather than a precedence rule.
pub enum NameFilter {
    /// Everything matches.
    Any,
    /// Case-folded substring, pre-lowered.
    Substring(String),
    /// A compiled regular expression, matched unanchored.
    Regex(Regex),
}

impl NameFilter {
    /// Compile the two mutually exclusive filter fields.
    pub fn compile(filter: Option<&str>, regex: Option<&str>) -> Result<Self, ToolError> {
        match (filter, regex) {
            (Some(_), Some(_)) => Err(ToolError::InvalidParams(
                "name at most one of 'filter' (substring) and 'regex'".to_string(),
            )),
            (Some(filter), None) => Ok(Self::Substring(filter.to_lowercase())),
            (None, Some(pattern)) => Regex::new(pattern).map(Self::Regex).map_err(|error| {
                ToolError::InvalidParams(format!("invalid regex '{pattern}': {error}"))
            }),
            (None, None) => Ok(Self::Any),
        }
    }

    /// Does this name belong in the answer?
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Substring(needle) => name.to_lowercase().contains(needle),
            Self::Regex(regex) => regex.is_match(name),
        }
    }
}

/// Ordering for a function listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FunctionSort {
    Address,
    Name,
    Size,
}

/// Ordering for a listing whose entries are only an address and a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NameSort {
    Address,
    Name,
}

/// A function listing request, as it reaches the worker.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FunctionQuery {
    pub offset: usize,
    pub limit: usize,
    pub filter: Option<String>,
    pub regex: Option<String>,
    pub min_size: Option<usize>,
    pub max_size: Option<usize>,
    pub sort_by: Option<FunctionSort>,
    pub descending: bool,
}

impl FunctionQuery {
    /// A plain paged listing: no filter, no ordering. What the internal
    /// callers (`survey_binary`, `export_funcs`) have always asked for.
    pub fn paged(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            ..Default::default()
        }
    }

    /// Compile the name half of this query.
    pub fn name_filter(&self) -> Result<NameFilter, ToolError> {
        NameFilter::compile(self.filter.as_deref(), self.regex.as_deref())
    }

    /// Is `size` inside the requested bounds?
    pub fn size_matches(&self, size: usize) -> bool {
        self.min_size.is_none_or(|min| size >= min) && self.max_size.is_none_or(|max| size <= max)
    }

    /// Does this query need every match in hand before it can answer?
    ///
    /// Sorting does; plain paging does not, and stays streaming so a listing
    /// of a large database still costs one pass and one page of memory.
    pub fn needs_full_scan(&self) -> bool {
        self.sort_by.is_some()
    }
}

/// Which references an xref listing keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    #[default]
    Any,
    Code,
    Data,
}

impl XrefKind {
    /// Does a reference with this code/data flag belong in the answer?
    pub fn keeps(self, is_code: bool) -> bool {
        match self {
            Self::Any => true,
            Self::Code => is_code,
            Self::Data => !is_code,
        }
    }
}

/// An xref listing request, as it reaches the worker.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct XrefQuery {
    pub offset: usize,
    pub limit: usize,
    pub kind: XrefKind,
    /// Collapse references that repeat the same `(from, to, type)` triple.
    /// A switch table can produce dozens of identical-looking entries.
    pub dedup: bool,
    /// Attach the enclosing function of each referencing address.
    pub include_function: bool,
}

impl XrefQuery {
    /// A plain paged listing: every reference, no extras.
    pub fn paged(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            ..Default::default()
        }
    }
}

/// Ordering for a string listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringSort {
    Address,
    Length,
    Content,
}

/// A string listing request, as it reaches the worker.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StringQuery {
    pub offset: usize,
    pub limit: usize,
    pub filter: Option<String>,
    pub regex: Option<String>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub sort_by: Option<StringSort>,
    pub descending: bool,
}

impl StringQuery {
    /// A plain paged listing, for the internal callers.
    pub fn paged(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            ..Default::default()
        }
    }

    /// A paged listing with the historical substring filter.
    pub fn filtered(offset: usize, limit: usize, filter: Option<String>) -> Self {
        Self {
            offset,
            limit,
            filter,
            ..Default::default()
        }
    }

    pub fn name_filter(&self) -> Result<NameFilter, ToolError> {
        NameFilter::compile(self.filter.as_deref(), self.regex.as_deref())
    }

    /// Is a string of `length` characters inside the requested bounds?
    pub fn length_matches(&self, length: usize) -> bool {
        self.min_length.is_none_or(|min| length >= min)
            && self.max_length.is_none_or(|max| length <= max)
    }

    pub fn needs_full_scan(&self) -> bool {
        self.sort_by.is_some()
    }
}

/// A string-content lookup, as it reaches the worker.
///
/// `find_string` and `xrefs_to_string` ask the same question — which strings
/// match this text? — and differ only in what they attach to each hit, so the
/// question is one type rather than the same six parameters threaded through
/// four layers twice. `max_xrefs` deliberately stays outside it: it bounds what
/// the xrefs tool renders per hit, not which strings are hits.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StringSearch {
    pub query: String,
    /// The whole string must equal `query`; mutually exclusive with `regex`.
    pub exact: bool,
    pub case_insensitive: bool,
    /// Treat `query` as a regular expression rather than a substring.
    pub regex: bool,
    pub offset: usize,
    pub limit: usize,
}

impl StringSearch {
    /// Every string in the database, in index order. An empty query matches
    /// everything, which is how the composite tools obtain the string-to-xref
    /// map they rank and join against.
    pub fn scan(limit: usize) -> Self {
        Self {
            case_insensitive: true,
            limit,
            ..Default::default()
        }
    }

    /// Compile the match half of this search.
    ///
    /// `exact` and `regex` are different questions about the same query, and
    /// answering both at once is meaningless: an anchored regex *is* the exact
    /// match a caller asking for both would want.
    pub fn matcher(&self) -> Result<StringMatcher, ToolError> {
        if self.regex {
            if self.exact {
                return Err(ToolError::InvalidParams(
                    "'exact' and 'regex' are mutually exclusive; anchor the regex instead"
                        .to_string(),
                ));
            }
            return RegexBuilder::new(&self.query)
                .case_insensitive(self.case_insensitive)
                .build()
                .map(StringMatcher::Regex)
                .map_err(|error| {
                    ToolError::InvalidParams(format!("invalid regex '{}': {error}", self.query))
                });
        }

        let normalized = self.fold(&self.query).into_owned();
        Ok(if self.exact {
            StringMatcher::Exact(normalized)
        } else {
            StringMatcher::Substring(normalized)
        })
    }

    /// Put `text` in the case the non-regex matchers compare in.
    ///
    /// Both sides of the comparison have to be folded the same way, so folding
    /// lives on the search that decides it rather than at the two call sites
    /// that walk the string list.
    pub fn fold<'a>(&self, text: &'a str) -> Cow<'a, str> {
        if self.case_insensitive {
            Cow::Owned(text.to_lowercase())
        } else {
            Cow::Borrowed(text)
        }
    }
}

/// How a string lookup decides whether a string is in the answer.
///
/// The compiled counterpart to `StringSearch`, as `NameFilter` is to the
/// listing queries.
pub enum StringMatcher {
    /// The whole string equals the query.
    Exact(String),
    /// The query appears anywhere in the string.
    Substring(String),
    /// A compiled regular expression.
    Regex(Regex),
}

impl StringMatcher {
    /// Does `content` match? `folded` is the case-folded form the caller has
    /// already computed, used by the two non-regex arms.
    pub fn matches(&self, content: &str, folded: &str) -> bool {
        match self {
            Self::Exact(query) => folded == query,
            Self::Substring(query) => folded.contains(query),
            Self::Regex(regex) => regex.is_match(content),
        }
    }
}

/// A local-type kind, as idalib reports it.
///
/// The names mirror `kind_from_tinfo` in idalib-sys exactly, plus `udt` — the
/// struct-or-union grouping IDA itself uses, which callers ask for far more
/// often than either half alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Struct,
    Union,
    Enum,
    Function,
    Pointer,
    Array,
    Typedef,
    Other,
    /// Struct or union.
    Udt,
}

impl TypeKind {
    /// Does idalib's kind string fall under this filter?
    pub fn keeps(self, kind: &str) -> bool {
        match self {
            Self::Struct => kind == "struct",
            Self::Union => kind == "union",
            Self::Enum => kind == "enum",
            Self::Function => kind == "function",
            Self::Pointer => kind == "pointer",
            Self::Array => kind == "array",
            Self::Typedef => kind == "typedef",
            Self::Other => kind == "other",
            Self::Udt => matches!(kind, "struct" | "union"),
        }
    }
}

/// Ordering for a type listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TypeSort {
    Ordinal,
    Name,
}

/// A type listing request: local types and structs.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TypeQuery {
    pub offset: usize,
    pub limit: usize,
    pub filter: Option<String>,
    pub regex: Option<String>,
    /// Only meaningful for `local_types`; `structs` lists UDTs only.
    pub kind: Option<TypeKind>,
    pub sort_by: Option<TypeSort>,
    pub descending: bool,
}

impl TypeQuery {
    /// A plain paged listing, for the internal callers.
    pub fn paged(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            ..Default::default()
        }
    }

    pub fn name_filter(&self) -> Result<NameFilter, ToolError> {
        NameFilter::compile(self.filter.as_deref(), self.regex.as_deref())
    }

    /// Does a type of this kind belong in the answer?
    pub fn kind_matches(&self, kind: &str) -> bool {
        self.kind.is_none_or(|want| want.keeps(kind))
    }

    pub fn needs_full_scan(&self) -> bool {
        self.sort_by.is_some()
    }

    /// Order `items` by this query's sort key, then take the requested page.
    pub fn sort<T>(
        &self,
        items: &mut Vec<T>,
        ordinal_of: impl Fn(&T) -> u32,
        name_of: impl Fn(&T) -> &str,
    ) {
        let Some(sort_by) = self.sort_by else {
            return;
        };
        match sort_by {
            TypeSort::Ordinal => items.sort_by_key(&ordinal_of),
            TypeSort::Name => items.sort_by(|a, b| name_of(a).cmp(name_of(b))),
        }
        if self.descending {
            items.reverse();
        }
        let start = self.offset.min(items.len());
        let end = start.saturating_add(self.limit).min(items.len());
        *items = items.drain(start..end).collect();
    }
}

/// A symbol listing request: globals, imports, exports.
///
/// The three differ only in which names they keep, so they share a query.
/// `module` is meaningful for imports, where it filters on the external
/// segment a symbol is imported through; the others ignore it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NameQuery {
    pub offset: usize,
    pub limit: usize,
    pub filter: Option<String>,
    pub regex: Option<String>,
    pub module: Option<String>,
    pub sort_by: Option<NameSort>,
    pub descending: bool,
}

impl NameQuery {
    /// A plain paged listing, for the internal callers.
    pub fn paged(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            ..Default::default()
        }
    }

    pub fn name_filter(&self) -> Result<NameFilter, ToolError> {
        NameFilter::compile(self.filter.as_deref(), self.regex.as_deref())
    }

    /// Does this import's module match the requested one? Case-folded
    /// substring, like the name filter's plain form.
    pub fn module_matches(&self, module: &str) -> bool {
        self.module
            .as_ref()
            .is_none_or(|want| module.to_lowercase().contains(&want.to_lowercase()))
    }

    pub fn needs_full_scan(&self) -> bool {
        self.sort_by.is_some()
    }

    /// Order `items` by this query's sort key, given accessors for the two
    /// sortable fields. Shared by the three symbol listings, whose entry types
    /// have no common trait but do have the same two fields.
    pub fn sort<T>(
        &self,
        items: &mut Vec<T>,
        address_of: impl Fn(&T) -> &str,
        name_of: impl Fn(&T) -> &str,
    ) {
        let Some(sort_by) = self.sort_by else {
            return;
        };
        match sort_by {
            // Rendered hex sorts as text; parse it back so 0x9 precedes 0x10.
            NameSort::Address => items.sort_by_key(|item| {
                u64::from_str_radix(address_of(item).trim_start_matches("0x"), 16).unwrap_or(0)
            }),
            NameSort::Name => items.sort_by(|a, b| name_of(a).cmp(name_of(b))),
        }
        if self.descending {
            items.reverse();
        }
        let start = self.offset.min(items.len());
        let end = start.saturating_add(self.limit).min(items.len());
        *items = items.drain(start..end).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_filter_matches_everything() {
        let filter = NameFilter::compile(None, None).expect("no filter is valid");
        assert!(filter.matches("anything"));
    }

    #[test]
    fn substring_filters_fold_case_on_both_sides() {
        let filter = NameFilter::compile(Some("MAIN"), None).expect("a substring filter is valid");
        assert!(filter.matches("do_main_thing"));
        assert!(!filter.matches("helper"));
    }

    #[test]
    fn regex_filters_are_anchorable() {
        let filter = NameFilter::compile(None, Some("^sub_")).expect("a valid regex compiles");
        assert!(filter.matches("sub_1000"));
        assert!(!filter.matches("do_sub_thing"));
    }

    #[test]
    fn naming_both_filters_is_an_error() {
        assert!(NameFilter::compile(Some("a"), Some("b")).is_err());
    }

    #[test]
    fn an_invalid_regex_is_a_parameter_error() {
        assert!(NameFilter::compile(None, Some("(unclosed")).is_err());
    }

    #[test]
    fn size_bounds_are_inclusive_on_both_ends() {
        let query = FunctionQuery {
            min_size: Some(10),
            max_size: Some(20),
            ..Default::default()
        };
        assert!(!query.size_matches(9));
        assert!(query.size_matches(10));
        assert!(query.size_matches(20));
        assert!(!query.size_matches(21));
    }

    #[test]
    fn an_open_ended_size_bound_only_constrains_one_side() {
        let query = FunctionQuery {
            min_size: Some(10),
            ..Default::default()
        };
        assert!(query.size_matches(usize::MAX));
        assert!(!query.size_matches(1));
    }

    #[test]
    fn only_sorting_forces_a_full_scan() {
        let paging = FunctionQuery::default();
        assert!(!paging.needs_full_scan());

        let sorted = FunctionQuery {
            sort_by: Some(FunctionSort::Size),
            ..Default::default()
        };
        assert!(sorted.needs_full_scan());
    }
}
