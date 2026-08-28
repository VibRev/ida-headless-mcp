//! MCP tool *output* types — the source of every `outputSchema` we publish.
//!
//! # Why these are mirrors and not the worker types
//!
//! Most tool bodies serialize a value from [`crate::ida::types`], which is the
//! idalib interaction layer and deliberately carries no MCP concerns (no
//! `schemars` derive, no MCP naming). Rather than push protocol derives down
//! into that layer, every response shape gets a mirror here that derives
//! `JsonSchema`. The mirrors are never constructed on the hot path: tools
//! serialize the worker type, so the worker type alone decides the bytes on the
//! wire. The mirrors exist only to *describe* those bytes.
//!
//! That split needs a guard, because a mirror that drifts from the worker type
//! would publish a lie. `mirrors_match_the_worker_types` in this module's test
//! section takes a fully-populated sample of each worker type, serializes it,
//! and round-trips it through the mirror with `deny_unknown_fields`, then
//! compares the re-serialized value to the original. A renamed, added, removed
//! or retyped field on either side fails that test. Adding a field to a worker
//! struct without mirroring it here is therefore a compile-and-test error, not
//! a silent schema regression.
//!
//! # Optional fields on "union" shapes
//!
//! Several tools accept either one address or a list, and answer with either
//! the single result or a `results` array of per-address entries. Those output
//! types model both arms with optional fields and document when each appears.
//! This is what the implementation actually returns; a tighter schema would be
//! a lie, and normalizing the two arms into one would break the wire.
//!
//! # The four tools that always wrap in `results`
//!
//! `basic_blocks`, `callees`, `callers` and `read_struct` are a harder case
//! than the unions above. They answer `{"results": [...]}` even for a single
//! address, the way `analyze_function` does — one shape, one schema, and the
//! supervisor wrapper does not apply. Answering one address with a *bare JSON
//! array* instead would make the root array-or-object, so no single schema of
//! `type: "object"` would cover them, and an `anyOf` root could not work
//! either — the supervisor wraps a bare-array worker payload into
//! `{"result": [...]}` at call time, but `adapt_output_schema_for_supervisor`
//! decides whether to advertise that wrapper by looking for `type: "object"`
//! at the root. An `anyOf` root reads as "not an object", so the supervisor
//! would advertise the wrapper unconditionally while the multi-address answer
//! arrived unwrapped. See [`BasicBlocksOutput`] and its neighbours.
//!
//! # `next_offset`
//!
//! One rule across every paginated tool: **`next_offset` is present exactly
//! when another page exists, and omitted otherwise.** It is never present and
//! null, so `"next_offset" in response` is a sound test for "another page
//! exists". Tools that serialize a struct get that from `skip_serializing_if`;
//! `search` and `find_bytes` assemble their pages with `json!`, where nothing
//! applies the `skip_serializing_if` the schema declares, so they have to
//! insert the key conditionally by hand.
//!
//! `search` and `find_bytes` scan under a ceiling and cannot always see past
//! it. They say so with `total_is_lower_bound` rather than by leaving
//! `next_offset` in an ambiguous state; see [`SearchEntry`].
//!
//! # `analysis_coverage`
//!
//! Every response type that reports a count, a list or a nullable slot drawn
//! from an index IDA's auto-analysis *writes* carries a mandatory
//! [`AnalysisCoverage`]. Read that type's documentation for the reasoning; the
//! short version is that `open_idb` returns before analysis settles, so those
//! answers are otherwise indistinguishable from settled ones.
//!
//! The block is not modelled in the worker types — for the same reason the
//! mirrors exist — so a tool splices it into the serialized payload. The
//! mirrors declare it because it really is on the wire; `assert_mirrors` has a
//! variant that splices the same key before round-tripping, so the drift guard
//! still holds.

mod composite;
mod controlflow;
mod coverage;
mod database;
mod decompile;
mod disassembly;
mod discovery;
mod editing;
mod functions;
mod memory;
mod metadata;
mod script;
mod search;
mod types;
mod xrefs;

pub use composite::*;
pub use controlflow::*;
pub use coverage::*;
pub use database::*;
pub use decompile::*;
pub use disassembly::*;
pub use discovery::*;
pub use editing::*;
pub use functions::*;
pub use memory::*;
pub use metadata::*;
pub use script::*;
pub use search::*;
pub use types::*;
pub use xrefs::*;

use rmcp::schemars::JsonSchema;
use std::sync::Arc;

/// Output schema for `T`, in the shape rmcp attaches to `Tool::output_schema`.
///
/// Thin alias so the `#[tool(output_schema = ...)]` attributes stay readable.
pub fn schema<T: JsonSchema + std::any::Any>() -> Arc<rmcp::model::JsonObject> {
    rmcp::handler::server::tool::schema_for_output::<T>()
}

#[cfg(test)]
mod tests;
