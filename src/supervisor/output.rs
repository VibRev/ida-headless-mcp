//! The output net, which is `vibrev_kit::output`.
//!
//! The kit owns the whole thing: the 50,000-character threshold, the
//! shape-preserving preview, the private spill directory, the LRU with a TTL,
//! and the proxy-header parsing that makes a `download_url` resolve from where
//! the client is standing. It lives there rather than here because three
//! engines need the same design — `jadx-headless-mcp` in Java is the third —
//! and a design copied three times by hand is one that drifts three ways.
//!
//! What is left here is the name this repository imports it under.

pub use vibrev_kit::output::{
    external_base_url, serve_output, Capped, Limits, OutputCache, OutputError, Prepared, Spill,
    Truncation,
};
