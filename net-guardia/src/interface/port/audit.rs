use crate::model::error::Error;

/// Port for audit trail persistence.
pub trait AuditPort: Send + Sync {
    fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error>;
}
