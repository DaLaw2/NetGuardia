pub mod acl;
pub mod api_keys;
pub mod audit;
pub mod auth;
pub mod byo;
pub mod default;
pub mod filter;
pub mod flow_trace;
pub mod fusion;
pub mod health;
pub mod logs;
pub mod ml;
pub mod model_upload;
pub mod notification;
pub mod rate_limit;
pub mod report;
pub mod response;
pub mod setup;
pub mod soar;
pub mod stats;
pub mod system;

/// Shared audit actor prefix for security-admin triggered events. Stable
/// wire string — WORM consumers filter on `SecurityAdmin@<username>` so
/// do not rename without coordinating audit-chain readers.
pub const AUDIT_ACTOR_SECURITY_ADMIN_PREFIX: &str = "SecurityAdmin";
