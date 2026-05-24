use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub actor: String,
    pub action: String,
    pub detail: String,
    pub created_at: String,
}
