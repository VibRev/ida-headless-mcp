//! Control-flow and call-graph output types.
//!
//! `basic_blocks`, `callees`, `callers` and `read_struct` always answer
//! `{"results": [...]}`, one entry per address, the way `analyze_function`
//! does — a single address included. Answering one address with a bare JSON
//! array would make the root array-or-object, which cannot be described by one
//! schema, and cannot be described by an `anyOf` root either: the supervisor
//! decides whether to advertise its `{"result": ...}` wrapper by testing for
//! `type: "object"` at the root, so an `anyOf` root would make the advertised
//! schema wrong for exactly the half of the calls that pass one address.
//!
//! The per-address entries key their payload as `basic_blocks`, `callees`,
//! `callers` or `struct`; those names are the wire contract.

use crate::ida::types as worker;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::coverage::AnalysisCoverage;
use super::functions::FunctionInfo;

/// One node of a function's control-flow graph.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasicBlockInfo {
    /// First address of the block, hex-formatted.
    pub start: String,
    /// One past the last address of the block, hex-formatted.
    pub end: String,
    /// `end - start`, in bytes.
    pub size: usize,
    /// How the block terminates: `normal`, `ret`, `cndret`, `noret`,
    /// `indjump`, `extern`, `error` or `unknown`.
    pub block_type: String,
    /// Start addresses of the blocks control can flow to, hex-formatted.
    pub successors: Vec<String>,
    /// Start addresses of the blocks control can arrive from, hex-formatted.
    pub predecessors: Vec<String>,
}

impl From<&worker::BasicBlockInfo> for BasicBlockInfo {
    fn from(block: &worker::BasicBlockInfo) -> Self {
        Self {
            start: block.start.clone(),
            end: block.end.clone(),
            size: block.size,
            block_type: block.block_type.clone(),
            successors: block.successors.clone(),
            predecessors: block.predecessors.clone(),
        }
    }
}

/// One address's blocks within a `basic_blocks` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasicBlocksEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// Blocks of the function containing `address`; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_blocks: Option<Vec<BasicBlockInfo>>,
    /// Why this address produced no graph; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `basic_blocks` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasicBlocksOutput {
    /// One entry per requested address, in request order.
    pub results: Vec<BasicBlocksEntry>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// A control-flow graph read before analysis settles is missing blocks the
    /// analyzer has not reached yet, and says so nowhere else.
    pub analysis_coverage: AnalysisCoverage,
}

/// One address's callees within a `callees` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalleesEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// Functions called by the function containing `address`; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callees: Option<Vec<FunctionInfo>>,
    /// Why this address produced no callees; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `callees` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalleesOutput {
    /// One entry per requested address, in request order.
    pub results: Vec<CalleesEntry>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Call edges are the clearest case there is: on a stock `/bin/cat` the
    /// database holds no call edges at all until analysis settles, and an empty
    /// `callees` list is indistinguishable from a function that calls nothing.
    pub analysis_coverage: AnalysisCoverage,
}

/// One address's callers within a `callers` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallersEntry {
    /// The address this entry answers for, hex-formatted.
    pub address: String,
    /// Functions calling the function containing `address`; absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callers: Option<Vec<FunctionInfo>>,
    /// Why this address produced no callers; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `callers` output.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallersOutput {
    /// One entry per requested address, in request order.
    pub results: Vec<CallersEntry>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// An empty `callers` list before analysis settles reads exactly like dead
    /// code. It usually is not.
    pub analysis_coverage: AnalysisCoverage,
}

/// `find_paths` output.
///
/// Paths are block-level: each one lists the start address of every basic
/// block on the route, so consecutive entries are edges in the CFG.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindPathsOutput {
    /// Routes found, each a list of block start addresses, hex-formatted.
    pub paths: Vec<Vec<String>>,
    /// Number of entries in `paths`, capped by `max_paths`.
    pub count: usize,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}

/// One function in a call graph.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphNode {
    /// Function entry address, hex-formatted.
    pub address: String,
    /// Function name.
    pub name: String,
    /// Size in bytes of the function's primary chunk.
    pub size: usize,
}

/// One call edge.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphEdge {
    /// Calling function's entry address, hex-formatted.
    pub from: String,
    /// Called function's entry address, hex-formatted.
    pub to: String,
}

/// A call graph reached from one root.
///
/// `edges` may name a node that `nodes` does not carry: the node cap stops the
/// walk from adding more functions but the edge that led there is still real.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphResult {
    /// Functions reached, root first in insertion order (map order in practice).
    pub nodes: Vec<CallGraphNode>,
    /// Call edges discovered during the walk.
    pub edges: Vec<CallGraphEdge>,
}

/// One root's graph within a multi-root `callgraph` call.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphBatchEntry {
    /// The root this entry answers for, hex-formatted.
    pub root: String,
    /// The graph reached from `root`; absent when the walk failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callgraph: Option<CallGraphResult>,
    /// Why this root produced no graph; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `callgraph` output.
///
/// One requested root fills `nodes`/`edges`; several fill `results`.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallGraphOutput {
    /// Functions reached from the single requested root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<CallGraphNode>>,
    /// Call edges discovered from the single requested root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edges: Option<Vec<CallGraphEdge>>,
    /// One entry per root when several were requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<Vec<CallGraphBatchEntry>>,
    /// Whether analysis had settled when this answer was read.
    ///
    /// Always present. `complete: false` means every count and list above is
    /// a lower bound, not a total.
    pub analysis_coverage: AnalysisCoverage,
}
