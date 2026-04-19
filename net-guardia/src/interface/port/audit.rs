use crate::model::error::Error;

/// Audit log entry returned by `list_audit_logs` and
/// `verify_audit_log_chain` APIs.
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub created_at: String,
}

/// Audit BC (supporting) — append-only WORM hash-chained audit log.
///
/// The append-only constraint is enforced by SQLite triggers
/// (`audit_log_no_update` / `audit_log_no_delete`), not by this trait.
pub trait AuditRepo: Send + Sync {
    /// Append a new audit entry. `detail` is typically a JSON blob.
    fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error>;

    /// Read audit entries whose `action` exactly matches, newest first,
    /// capped at `limit`. Drives the fusion explain endpoint, which
    /// filters on `fused_threat_emitted` rather than walking the full
    /// chain for every request.
    fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error>;

    /// Walk the full chain and verify every `row_hash` matches
    /// `H(ts || actor || action || detail || prev_hash)`. Returns the number
    /// of entries verified. Errors on the first broken link.
    fn verify_audit_log_chain(&self) -> Result<usize, Error>;
}
