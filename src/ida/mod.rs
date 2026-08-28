//! IDA Pro integration module.
//!
//! This module provides a headless IDA Pro interface via the idalib crate.
//! It uses a channel-based worker pattern to ensure IDA operations run on the main thread
//! (IDA types are not thread-safe).

pub mod handlers;
pub mod hexrays;
pub mod install;
pub mod int_spec;
pub(crate) mod leftover;
pub mod lock;
mod main_loop;
pub mod observability;
pub mod pool;
pub mod query;
#[cfg(target_os = "windows")]
mod registry_isolation;
// `pub(crate)`, not `pub`: the child-error classifier here is what turns a
// worker's `isError: true` into a typed `ToolError`, and `server`'s tests assert
// that a tool reporting failure still reaches it.
pub(crate) mod remote;
pub mod request;
pub mod scan;
pub(crate) mod sdk_bridge;
pub mod signature;
pub mod types;
pub mod worker;

pub use main_loop::{init_ida_library, run_ida_loop, IdaInitState, IdaRuntimePolicy};
pub use request::IdaRequest;
pub use types::*;
pub use worker::IdaWorker;
