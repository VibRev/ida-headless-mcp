//! Explicit multi-database supervisor.
//!
//! The supervisor owns the session table and the worker pool; every analysis
//! tool it advertises is a native `#[tool]` from [`crate::server`], routed to
//! the worker that owns the requested `database` session.

pub mod legacy_sse;
pub mod output;
pub mod resource;
pub mod server;
pub mod session;
pub mod tool_filter;

pub use legacy_sse::{LegacySseConfig, LegacySseService};
pub use output::{Capped, OutputCache};
pub use server::SupervisorServer;
pub use session::{
    CloseSessionResult, OpenSessionRequest, OpenSessionResult, OpenedSessionInfo, SessionInfo,
    SessionManager,
};
pub use tool_filter::{supervisor_policy, supervisor_taxonomy, validate_unsafe_gate};
