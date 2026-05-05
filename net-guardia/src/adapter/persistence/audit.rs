use std::fmt::Write;

use async_trait::async_trait;
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::Database;
use crate::domain::common::audit::AuditLogEntry;
use crate::domain::common::error::Error;
use crate::domain::common::error::database::DatabaseError;
use crate::interface::audit::AuditRepo;

fn audit_row_hash(ts: &str, actor: &str, action: &str, detail: &str, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    for part in [ts, actor, action, detail, prev_hash] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    let out = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in out {
        let _ = write!(&mut hex, "{:02x}", byte);
    }
    hex
}

impl Database {
    pub async fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error> {
        let actor = actor.to_string();
        let action = action.to_string();
        let detail = detail.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let ts = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                let tx = conn.transaction()?;
                let prev_hash: String = tx
                    .query_row("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |row| {
                        row.get(0)
                    })
                    .unwrap_or_default();
                let row_hash = audit_row_hash(&ts, &actor, &action, &detail, &prev_hash);
                tx.execute(
                    "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, row_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![ts, actor, action, detail, prev_hash, row_hash],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, actor, action, detail, ts FROM audit_log ORDER BY id DESC LIMIT 200")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(AuditLogEntry {
                            id: row.get(0)?,
                            actor: row.get(1)?,
                            action: row.get(2)?,
                            detail: row.get(3)?,
                            created_at: row.get(4)?,
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(rows)
            })
            .await
    }

    pub async fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        let action = action.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, actor, action, detail, ts FROM audit_log WHERE action = ?1 ORDER BY id DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![action, limit], |row| {
                        Ok(AuditLogEntry {
                            id: row.get(0)?,
                            actor: row.get(1)?,
                            action: row.get(2)?,
                            detail: row.get(3)?,
                            created_at: row.get(4)?,
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(rows)
            })
            .await
    }

    pub async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut expected_prev = if after_id > 0 {
                    conn.query_row(
                        "SELECT row_hash FROM audit_log WHERE id = ?1",
                        params![after_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap_or_default()
                } else {
                    String::new()
                };

                let mut stmt = conn.prepare(
                    "SELECT id, ts, actor, action, detail, prev_hash, row_hash \
                     FROM audit_log WHERE id > ?1 ORDER BY id ASC",
                )?;
                let mut rows = stmt.query(params![after_id])?;

                let mut count = 0usize;
                let mut last_id = after_id;
                while let Some(row) = rows.next()? {
                    let id: i64 = row.get(0)?;
                    let ts: String = row.get(1)?;
                    let actor: String = row.get(2)?;
                    let action: String = row.get(3)?;
                    let detail: String = row.get(4)?;
                    let prev_hash: String = row.get(5)?;
                    let row_hash: String = row.get(6)?;

                    if prev_hash != expected_prev {
                        return Err(DatabaseError::AuditPrevHashMismatch(id, expected_prev, prev_hash).into());
                    }
                    let computed = audit_row_hash(&ts, &actor, &action, &detail, &prev_hash);
                    if computed != row_hash {
                        return Err(DatabaseError::AuditRowHashMismatch(id, computed, row_hash).into());
                    }
                    expected_prev = row_hash;
                    last_id = id;
                    count += 1;
                }
                Ok((count, last_id))
            })
            .await
    }
}

#[async_trait]
impl AuditRepo for Database {
    async fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error> {
        self.insert_audit_log(actor, action, detail).await
    }

    async fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        self.list_audit_logs_by_action(action, limit).await
    }

    async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error> {
        self.verify_audit_log_chain(after_id).await
    }
}
