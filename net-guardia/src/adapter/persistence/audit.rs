use std::fmt::Write;

use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::common::error::database::DatabaseError;
use crate::interface::port::audit::{AuditLogEntry, AuditRepo};

/// Compute the row hash for an audit_log entry.
/// Formula: sha256_hex(ts || 0x00 || actor || 0x00 || action || 0x00 || detail || 0x00 || prev_hash)
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
    /// Insert an audit trail entry. Runs in a transaction so the (prev_hash
    /// lookup, row_hash compute, insert) sequence is atomic and serializable.
    pub fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error> {
        let mut conn = self.conn()?;
        let ts = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let tx = conn.transaction()?;
        let prev_hash: String = tx
            .query_row("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap_or_default();

        let row_hash = audit_row_hash(&ts, actor, action, detail, &prev_hash);
        tx.execute(
            "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, row_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![ts, actor, action, detail, prev_hash, row_hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// List recent audit log entries (most recent first, max 200).
    pub fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
        let conn = self.conn()?;
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
    }

    /// Read audit entries whose `action` matches exactly, newest-first,
    /// capped at `limit`. Drives the fusion explain endpoint.
    pub fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        let conn = self.conn()?;
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
    }

    /// Walk the entire audit_log in id order and verify the hash chain.
    /// Returns `Ok(count)` on success; returns `Err` at the first mismatch,
    /// naming the offending row id and the kind of mismatch.
    pub fn verify_audit_log_chain(&self) -> Result<usize, Error> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT id, ts, actor, action, detail, prev_hash, row_hash FROM audit_log ORDER BY id ASC")?;
        let mut rows = stmt.query([])?;

        let mut expected_prev = String::new();
        let mut count = 0usize;
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
            count += 1;
        }
        Ok(count)
    }
}

impl AuditRepo for Database {
    fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error> {
        self.insert_audit_log(actor, action, detail)
    }

    fn list_audit_logs_by_action(&self, action: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        self.list_audit_logs_by_action(action, limit)
    }

    fn verify_audit_log_chain(&self) -> Result<usize, Error> {
        self.verify_audit_log_chain()
    }
}
