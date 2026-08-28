//! Auto-analysis readiness and the `analysis_coverage` block.

use crate::ida::types as worker;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Whether this database's analysis has settled.
///
/// Read `auto_is_ok` and nothing else. The other three fields are IDA's own
/// bookkeeping and read as contradictory when taken as readiness signals, which
/// is what they look like: a freshly opened shared cache reports
/// `analysis_running: true` beside `auto_state: AU_NONE`, and both are correct.
///
/// `session_id` is added by the supervisor-facing worker before the value
/// leaves the process and stripped again on the way back out, so it is present
/// on the worker's own MCP face and absent on the supervisor's.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisStatusOutput {
    /// True when IDA's auto-analysis is enabled for this database.
    pub auto_enabled: bool,
    /// The readiness signal. True when analysis has settled, so xrefs,
    /// decompilation and every count are the database's final answer; false
    /// means run analyze_funcs and read again. This is the only field to branch
    /// on.
    pub auto_is_ok: bool,
    /// IDA's `AU_*` state name, for diagnostics only — not a readiness signal.
    /// It is not monotonic and does not converge: a fully analyzed binary
    /// reports `AU_NONE`, the same value it reports the instant it is opened.
    /// Never conclude "analysis is done" from it.
    pub auto_state: String,
    /// Numeric form of `auto_state`, with the same caveat.
    pub auto_state_id: i32,
    /// True while an analysis pass is in flight. Distinguishes "wait and
    /// re-read" from "analysis will not finish on its own, call analyze_funcs".
    /// Independent of `auto_state`, which may read `AU_NONE` throughout.
    pub analysis_running: bool,
    /// Worker session that answered; absent on the supervisor's face.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// Key every read tool's response carries the coverage block under.
///
/// Sorts near the front of a serialized object, which is where a reader — human
/// or model — should meet it.
pub const ANALYSIS_COVERAGE_KEY: &str = "analysis_coverage";

/// How much of the engine's analysis the answer above was read from.
///
/// # Why this exists
///
/// `open_idb` returns as soon as the database is loadable, not when analysis
/// has settled. A tool called in that window answers from a half-built
/// database: on a stock `/bin/cat`, `list_funcs` reports 66 functions where the
/// settled answer is 161, and `survey_binary` reports zero call edges where the
/// settled answer is 253. Nothing in either payload distinguishes the two. That
/// is worse than an error — a client reads a well-formed number and reasons
/// from it.
///
/// So every tool whose answer is a count, a list or a nullable slot drawn from
/// an index the analyzer *writes* carries this block, unconditionally. It is
/// never `Option`, never `skip_serializing_if`: a completeness marker that
/// disappears is a completeness marker that vanishes exactly when the analysis
/// is in the state it was meant to warn about.
///
/// # Reading it
///
/// [`complete`](Self::complete) is the whole answer for a client that wants
/// one bool. [`state`](Self::state) adds the third case, `unknown`, for when
/// the engine could not be asked. Neither requires decoding IDA's `AU_*` state
/// machine, which is not usable as a readiness signal anyway: a settled
/// `/bin/cat` still reports `AU_NONE`.
///
/// # When it is sampled
///
/// Before the payload is read, not after. Analysis completeness only moves
/// forwards (until an edit re-dirties the database), so a "settled" reading
/// taken first cannot be invalidated by the read that follows it, while a
/// "partial" reading taken first may turn out to have been pessimistic. That
/// asymmetry is deliberate: over-reporting incompleteness costs a wasted
/// re-read, under-reporting it costs a wrong conclusion.
///
/// # Filling it in another engine
///
/// The field name and the meaning of every member are the cross-engine
/// contract; only [`engine_state`](Self::engine_state) is allowed to be
/// engine-shaped. For Binary Ninja the concept is analysis *convergence*:
///
/// - `complete` — `bv.analysis_info.state == AnalysisState.IdleState` and no
///   further update is queued, i.e. what `update_analysis_and_wait()` waits
///   for. Anything else, including `IdleState` reached with pending function
///   updates, is `false`.
/// - `state` — `Complete` for the above, `Partial` while
///   `DisassembleState`/`AnalyzeState` is in flight or an update is pending,
///   `Unknown` if the view cannot be queried.
/// - `analysis_running` — `state != IdleState`.
/// - `engine_state` — the `AnalysisState` variant name, verbatim.
/// - `note` — same two sentences, with `update_analysis_and_wait()` named in
///   place of `analyze_funcs`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisCoverage {
    /// True when the engine's analysis had settled before this answer was read.
    ///
    /// False means the counts and lists above are a floor, not a total. Exactly
    /// `state == Complete`; it exists so the cheapest check a client can write
    /// is also the correct one.
    pub complete: bool,
    /// The same answer with the "could not tell" case spelled out.
    pub state: AnalysisCoverageState,
    /// True while the engine was still analyzing when this answer was read.
    ///
    /// Distinguishes "wait and re-read" (`true`) from "analysis is not going to
    /// finish on its own, ask for it" (`false` with `complete` false).
    pub analysis_running: bool,
    /// The engine's own state name, for diagnostics only.
    ///
    /// IDA fills the `AU_*` constant (`AU_NONE`, `AU_FINAL`, ...); Binary Ninja
    /// fills the `AnalysisState` variant. Never branch on it — it is not
    /// comparable across engines, and in IDA it is not even monotonic.
    pub engine_state: String,
    /// One line saying what the state above means for the answer it rides on.
    pub note: String,
}

/// [`AnalysisCoverage::state`] in three cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisCoverageState {
    /// Analysis had settled: the answer is the engine's final one.
    Complete,
    /// Analysis had not settled: the answer is a lower bound.
    Partial,
    /// The engine could not be asked, so completeness is not known. Treat it
    /// exactly as `Partial`; it is spelled differently only so a client can
    /// tell "still working" from "no idea".
    Unknown,
}

impl AnalysisCoverage {
    /// Coverage as IDA's auto-analysis state reports it.
    ///
    /// `auto_is_ok` is the only member of [`worker::AnalysisStatus`] that
    /// actually answers "has analysis settled". `auto_state` is kept for
    /// diagnostics and nothing else: a fully analyzed `/bin/cat` reports
    /// `AU_NONE`, the same value it reports the instant it is opened.
    pub fn from_ida(status: &worker::AnalysisStatus) -> Self {
        if status.auto_is_ok {
            return Self {
                complete: true,
                state: AnalysisCoverageState::Complete,
                analysis_running: status.analysis_running,
                engine_state: status.auto_state.clone(),
                note: "Auto-analysis had settled when this was read; the counts \
                       and lists are the database's final answer."
                    .to_string(),
            };
        }

        let note = if status.analysis_running {
            "Auto-analysis was still running when this was read; every count and \
             list here is a lower bound. Poll analysis_status until auto_is_ok, \
             or call analyze_funcs, then read again."
        } else {
            "Auto-analysis has not settled and is not running; every count and \
             list here is a lower bound. Call analyze_funcs, then read again."
        };
        Self {
            complete: false,
            state: AnalysisCoverageState::Partial,
            analysis_running: status.analysis_running,
            engine_state: status.auto_state.clone(),
            note: note.to_string(),
        }
    }

    /// Coverage for when the engine could not be asked.
    ///
    /// Never reports `complete`: "we failed to check" and "it is finished" are
    /// not the same claim, and only one of them is safe to guess.
    pub fn unknown(reason: &str) -> Self {
        Self {
            complete: false,
            state: AnalysisCoverageState::Unknown,
            analysis_running: false,
            engine_state: "unavailable".to_string(),
            note: format!(
                "Analysis state could not be read ({reason}), so it is unknown whether \
                 the counts and lists here are complete. Treat them as a lower bound."
            ),
        }
    }

    /// This block as JSON, built without a fallible serializer.
    ///
    /// Tools splice the block into an already-serialized payload, and a
    /// splice that can fail would put the schema's one mandatory field back in
    /// the "sometimes missing" category this whole type exists to escape.
    /// `analysis_coverage_json_matches_serde` pins this against the derive.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "complete": self.complete,
            "state": match self.state {
                AnalysisCoverageState::Complete => "complete",
                AnalysisCoverageState::Partial => "partial",
                AnalysisCoverageState::Unknown => "unknown",
            },
            "analysis_running": self.analysis_running,
            "engine_state": self.engine_state,
            "note": self.note,
        })
    }
}
