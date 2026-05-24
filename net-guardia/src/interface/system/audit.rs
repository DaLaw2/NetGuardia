use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::common::audit::AuditLogEntry;

#[async_trait]
pub trait AuditRepo: Send + Sync {
    async fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error>;
    async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error>;
    async fn list_audit_logs_by_src_ip(&self, src_ip: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error>;
    async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error>;
}
