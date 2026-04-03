pub mod constants;

// Backward-compatible re-exports: `crate::model::config::*` continues to resolve
// the domain config types that previously lived at `crate::model::system::config::*`.
pub use super::system::config::*;
