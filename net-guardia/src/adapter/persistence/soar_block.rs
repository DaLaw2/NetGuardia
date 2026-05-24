use rusqlite::{Error as RusqliteError, params};

use super::Database;
use crate::common::error::Error;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::interface::response::playbook_data::{ActiveBlockView, PendingUnblock};

fn active_block_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ActiveBlockView> {
    Ok(ActiveBlockView {
        id: row.get::<_, i64>(0)?,
        source_ip: row.get::<_, String>(1)?,
        playbook_id: row.get::<_, i64>(2)?,
        expires_at: row.get::<_, String>(3)?,
    })
}

impl Database {
    pub async fn count_active_soar_blocks(&self) -> Result<u32, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let count: u32 = conn.query_row(
                    "SELECT COUNT(*) FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')",
                    [],
                    |row| row.get(0),
                )?;
                Ok(count)
            })
            .await
    }

    pub async fn list_expired_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE expires_at <= datetime('now') AND unblocked_at IS NULL",
                )?;
                let rows = stmt
                    .query_map([], active_block_from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn find_soar_block_by_id(&self, id: i64) -> Result<Option<ActiveBlockView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let result = conn.query_row(
                    "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE id = ?1",
                    params![id],
                    active_block_from_row,
                );
                match result {
                    Ok(block) => Ok(Some(block)),
                    Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    pub async fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE soar_block_rules SET unblocked_at = datetime('now') WHERE id = ?1",
                    params![id],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn list_active_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')"
                )?;
                let rows = stmt
                    .query_map([], active_block_from_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error> {
        let source_ip = source_ip.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO pending_unblock (source_ip) VALUES (?1)",
                    params![source_ip],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_ip, retry_count, exhausted_at, last_error
                     FROM pending_unblock ORDER BY id",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(PendingUnblock {
                        id: row.get::<_, i64>(0)?,
                        source_ip: row.get::<_, String>(1)?,
                        retry_count: row.get::<_, i64>(2)?,
                        exhausted_at: row.get::<_, Option<String>>(3)?,
                        last_error: row.get::<_, Option<String>>(4)?,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }

    pub async fn delete_pending_unblock(&self, id: i64) -> Result<(), Error> {
        self.pool
            .conn_and_then(move |conn| {
                conn.execute("DELETE FROM pending_unblock WHERE id = ?1", params![id])?;
                Ok(())
            })
            .await
    }

    pub async fn mark_pending_unblock_exhausted(&self, id: i64, last_error: &str) -> Result<(), Error> {
        let last_error = last_error.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE pending_unblock
                     SET exhausted_at = datetime('now'), last_error = ?2
                     WHERE id = ?1",
                    params![id, last_error],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error> {
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "UPDATE pending_unblock SET retry_count = retry_count + 1 WHERE id = ?1",
                    params![id],
                )?;
                Ok(())
            })
            .await
    }

    pub async fn commit_soar_block_to_db(
        &self,
        source_ip: &str,
        ip_version: IpVersion,
        playbook_id: i64,
        expires_at: &str,
    ) -> Result<i64, Error> {
        let ip_version = ip_version.as_u8();
        let source_ip = source_ip.to_string();
        let expires_at = expires_at.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let existing_acl_count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM acl_rules
                     WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
                    params![ip_version, "source", "blacklist", source_ip.as_str(), 0i64],
                    |row| row.get(0),
                )?;
                let active_soar_owned_count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM soar_block_rules
                     WHERE source_ip = ?1
                       AND unblocked_at IS NULL
                       AND expires_at > datetime('now')
                       AND created_acl_rule = 1
                       AND preserve_acl_on_unblock = 0",
                    params![source_ip.as_str()],
                    |row| row.get(0),
                )?;
                let created_acl_rule = existing_acl_count == 0 || active_soar_owned_count > 0;
                tx.execute(
                    "INSERT INTO soar_block_rules (source_ip, playbook_id, expires_at, created_acl_rule)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![source_ip.as_str(), playbook_id, expires_at, created_acl_rule as i64],
                )?;
                let soar_block_id = tx.last_insert_rowid();
                tx.execute(
                    "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![ip_version, "source", "blacklist", source_ip.as_str(), 0i64],
                )?;
                tx.commit()?;
                Ok(soar_block_id)
            })
            .await
    }

    pub async fn commit_soar_unblock_to_db(
        &self,
        soar_block_id: i64,
        ip_version: IpVersion,
        source_ip: &str,
    ) -> Result<(), Error> {
        let ip_version = ip_version.as_u8();
        let source_ip = source_ip.to_string();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let should_delete_acl: bool = tx.query_row(
                    "SELECT created_acl_rule = 1
                            AND preserve_acl_on_unblock = 0
                            AND NOT EXISTS (
                                SELECT 1 FROM soar_block_rules
                                WHERE id != ?1
                                  AND source_ip = ?2
                                  AND unblocked_at IS NULL
                                  AND expires_at > datetime('now')
                            )
                     FROM soar_block_rules WHERE id = ?1",
                    params![soar_block_id, source_ip.as_str()],
                    |row| row.get(0),
                )?;
                if should_delete_acl {
                    tx.execute(
                        "DELETE FROM acl_rules
                         WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
                        params![ip_version, "source", "blacklist", source_ip.as_str(), 0i64],
                    )?;
                }
                tx.execute(
                    "UPDATE soar_block_rules SET unblocked_at = datetime('now') WHERE id = ?1",
                    params![soar_block_id],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_plane::acl_rule::AclRuleView;
    use crate::domain::data_plane::direction::FlowDirection;
    use crate::domain::data_plane::list_type::ListType;

    const SOURCE_IP: &str = "198.51.100.42";
    const ACTIVE_UNTIL: &str = "2999-01-01 00:00:00";

    fn acl_contains(rules: &[AclRuleView], ip: &str) -> bool {
        rules.iter().any(|rule| {
            rule.ip_address == ip && rule.direction == FlowDirection::Source && rule.list_type == ListType::Black
        })
    }

    #[tokio::test]
    async fn overlapping_soar_blocks_keep_acl_until_last_block_unblocks() {
        let db = Database::new(":memory:").await.expect("database");
        let first = db
            .commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, ACTIVE_UNTIL)
            .await
            .expect("first block");
        let second = db
            .commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 2, ACTIVE_UNTIL)
            .await
            .expect("second block");

        db.commit_soar_unblock_to_db(first, IpVersion::V4, SOURCE_IP)
            .await
            .expect("first unblock");
        assert!(
            acl_contains(&db.list_acl_rules().await.expect("acl after first unblock"), SOURCE_IP),
            "ACL row must stay while an overlapping SOAR block is active"
        );

        db.commit_soar_unblock_to_db(second, IpVersion::V4, SOURCE_IP)
            .await
            .expect("second unblock");
        assert!(
            !acl_contains(&db.list_acl_rules().await.expect("acl after second unblock"), SOURCE_IP),
            "last SOAR-owned block should remove the SOAR-owned ACL row"
        );
    }

    #[tokio::test]
    async fn manual_acl_existing_before_soar_block_is_preserved_on_unblock() {
        let db = Database::new(":memory:").await.expect("database");
        db.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Source,
            ListType::Black,
            SOURCE_IP,
            0,
            false,
        )
        .await
        .expect("manual acl");
        let block = db
            .commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, ACTIVE_UNTIL)
            .await
            .expect("soar block");

        db.commit_soar_unblock_to_db(block, IpVersion::V4, SOURCE_IP)
            .await
            .expect("unblock");

        assert!(
            acl_contains(&db.list_acl_rules().await.expect("acl rules"), SOURCE_IP),
            "pre-existing manual ACL row must remain after SOAR unblock"
        );
    }
}
