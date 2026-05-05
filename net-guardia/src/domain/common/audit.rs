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
