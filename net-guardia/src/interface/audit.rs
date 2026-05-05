use async_trait::async_trait;

use crate::domain::common::audit::AuditLogEntry;
use crate::domain::common::error::Error;

/// Audit BC (supporting) — append-only WORM hash-chained audit log.
///
/// The append-only constraint is enforced by SQLite triggers
/// (`audit_log_no_update` / `audit_log_no_delete`), not by this trait.
#[async_trait]
pub trait AuditRepo: Send + Sync {
    /// Append a new audit entry. `detail` is typically a JSON blob.
    async fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error>;

    /// Read audit entries whose `action` exactly matches, newest first,
    /// capped at `limit`. Drives the fusion explain endpoint, which
    /// filters on `fused_threat_emitted` rather than walking the full
    /// chain for every request.
    async fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error>;

    /// Walk the chain from `after_id` onward, verifying every `row_hash`.
    /// Pass `0` to verify the full table. Returns `(verified_count, last_id)`.
    async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error>;
}
