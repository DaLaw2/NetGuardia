use std::fmt::Write;

use async_trait::async_trait;
use chrono::Utc;
use rusqlite::{Error as RusqliteError, params};
use sha2::{Digest, Sha256};

use super::Database;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::domain::common::audit::AuditLogEntry;
use crate::interface::system::audit::AuditRepo;

fn audit_row_hash(ts: &str, actor: &str, action: &str, detail: &str, prev_hash: &str) -> String {
    let mut h = Sha256::new();
    for part in [ts, actor, action, detail, prev_hash] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part.as_bytes());
    }
    hash_to_hex(h)
}

fn hash_to_hex(h: Sha256) -> String {
    let out = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in out {
        // SAFETY: write! on a String is infallible.
        let _ = write!(&mut hex, "{:02x}", byte);
    }
    hex
}

fn audit_log_entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditLogEntry> {
    Ok(AuditLogEntry {
        id: row.get(0)?,
        actor: row.get(1)?,
        action: row.get(2)?,
        detail: row.get(3)?,
        created_at: row.get(4)?,
    })
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
                let prev_hash: String =
                    match tx.query_row("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1", [], |row| {
                        row.get(0)
                    }) {
                        Ok(hash) => hash,
                        Err(RusqliteError::QueryReturnedNoRows) => String::new(),
                        Err(err) => return Err(err.into()),
                    };
                let row_hash = audit_row_hash(&ts, &actor, &action, &detail, &prev_hash);
                tx.execute(
                    "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, row_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![ts, actor, action, detail, prev_hash, row_hash],
                )?;
                tx.commit()?;
                Ok::<(), Error>(())
            })
            .await
    }

    pub async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, actor, action, detail, ts FROM audit_log ORDER BY id DESC LIMIT 200")?;
                let rows = stmt
                    .query_map([], audit_log_entry_from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<Vec<AuditLogEntry>, Error>(rows)
            })
            .await
    }

    pub async fn list_audit_logs_by_src_ip(&self, src_ip: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        let src_ip = src_ip.to_string();
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, actor, action, detail, ts FROM audit_log \
                     WHERE action = 'fused_threat_emitted' \
                       AND json_valid(detail) \
                       AND json_extract(detail, '$.src_ip') = ?1 \
                     ORDER BY id ASC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![src_ip, limit], audit_log_entry_from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<Vec<AuditLogEntry>, Error>(rows)
            })
            .await
    }

    pub async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut expected_prev = if after_id > 0 {
                    match conn.query_row(
                        "SELECT row_hash FROM audit_log WHERE id = ?1",
                        params![after_id],
                        |row| row.get::<_, String>(0),
                    ) {
                        Ok(hash) => hash,
                        Err(RusqliteError::QueryReturnedNoRows) => {
                            return Err(DatabaseError::AuditCheckpointMissing(after_id).into());
                        }
                        Err(err) => return Err(err.into()),
                    }
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
                Ok::<(usize, i64), Error>((count, last_id))
            })
            .await
    }
}

#[async_trait]
impl AuditRepo for Database {
    async fn insert_audit_log(&self, actor: &str, action: &str, detail: &str) -> Result<(), Error> {
        self.insert_audit_log(actor, action, detail).await
    }

    async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
        self.list_audit_logs().await
    }

    async fn list_audit_logs_by_src_ip(&self, src_ip: &str, limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
        self.list_audit_logs_by_src_ip(src_ip, limit).await
    }

    async fn verify_audit_log_chain(&self, after_id: i64) -> Result<(usize, i64), Error> {
        self.verify_audit_log_chain(after_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::Database;
    use crate::domain::common::config::constants::{FUSION_AUDIT_ACTION, FUSION_AUDIT_ACTOR};

    #[tokio::test]
    async fn verify_audit_chain_rejects_missing_checkpoint() {
        let db = Database::new(":memory:").await.expect("test db");

        assert!(db.verify_audit_log_chain(42).await.is_err());
    }

    #[tokio::test]
    async fn list_audit_logs_by_src_ip_uses_indexed_detail_filter() {
        let db = Database::new(":memory:").await.expect("test db");
        let matching_early = serde_json::json!({
            "src_ip": "192.0.2.10",
            "attack_type": "brute_force",
        })
        .to_string();
        let nonmatching = serde_json::json!({
            "src_ip": "198.51.100.7",
            "attack_type": "scan",
        })
        .to_string();
        let matching_late = serde_json::json!({
            "src_ip": "192.0.2.10",
            "attack_type": "exploit",
        })
        .to_string();

        db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &matching_early)
            .await
            .expect("insert matching fusion audit");
        db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &nonmatching)
            .await
            .expect("insert nonmatching fusion audit");
        db.insert_audit_log("OtherActor", "other_action", "{{not json")
            .await
            .expect("insert malformed non-fusion audit");
        db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &matching_late)
            .await
            .expect("insert second matching fusion audit");

        let entries = db
            .list_audit_logs_by_src_ip("192.0.2.10", 10)
            .await
            .expect("list fusion evidence");

        assert_eq!(entries.len(), 2);
        assert!(
            entries[0].id < entries[1].id,
            "fusion explain query should return oldest evidence first"
        );
        assert!(entries.iter().all(|entry| entry.action == FUSION_AUDIT_ACTION));
        assert!(entries.iter().all(|entry| entry.detail.contains("192.0.2.10")));
    }

    #[tokio::test]
    async fn list_audit_logs_by_src_ip_respects_limit() {
        let db = Database::new(":memory:").await.expect("test db");

        for attack_type in ["a", "b", "c"] {
            let detail = serde_json::json!({
                "src_ip": "203.0.113.10",
                "attack_type": attack_type,
            })
            .to_string();
            db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &detail)
                .await
                .expect("insert fusion audit");
        }

        let entries = db
            .list_audit_logs_by_src_ip("203.0.113.10", 2)
            .await
            .expect("list fusion evidence");

        assert_eq!(entries.len(), 2);
        assert!(entries[0].id < entries[1].id);
    }
}
