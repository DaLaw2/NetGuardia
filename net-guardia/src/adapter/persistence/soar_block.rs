use rusqlite::params;

use super::Database;
use crate::interface::port::db_admin::DbAdminRepo;
use crate::model::error::Error;

impl Database {
    /// Test-only helper: direct insert of a SOAR block rule row. Production
    /// code goes through `commit_soar_block_to_db` which atomically writes
    /// both `soar_block_rules` and `acl_rules` under a transaction.
    #[cfg(test)]
    pub fn insert_soar_block_rule(&self, source_ip: &str, playbook_id: i64, expires_at: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO soar_block_rules (source_ip, playbook_id, expires_at) VALUES (?1, ?2, ?3)",
            params![source_ip, playbook_id, expires_at],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn count_active_soar_blocks(&self) -> Result<u32, Error> {
        let conn = self.conn()?;
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_expired_soar_blocks(&self) -> Result<Vec<(i64, String, i64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, playbook_id FROM soar_block_rules WHERE expires_at <= datetime('now') AND unblocked_at IS NULL"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Get a single SOAR block rule by ID, returning (id, source_ip, playbook_id, expires_at).
    pub fn find_soar_block_by_id(&self, id: i64) -> Result<Option<(i64, String, i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt =
            conn.prepare("SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE id = ?1")?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    pub fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE soar_block_rules SET unblocked_at = datetime('now') WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn list_active_soar_blocks(&self) -> Result<Vec<(i64, String, i64, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, playbook_id, expires_at FROM soar_block_rules WHERE unblocked_at IS NULL AND expires_at > datetime('now')"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO pending_unblock (source_ip) VALUES (?1)",
            params![source_ip],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_pending_unblocks(&self) -> Result<Vec<(i64, String, i64)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT id, source_ip, retry_count FROM pending_unblock ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn delete_pending_unblock(&self, id: i64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM pending_unblock WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE pending_unblock SET retry_count = retry_count + 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}

impl DbAdminRepo for Database {
    /// Commit a SOAR-driven block to both `soar_block_rules` and
    /// `acl_rules` in one transaction. Callers must have already installed
    /// the eBPF block before calling this, and are responsible for removing
    /// the eBPF block if this returns Err.
    fn commit_soar_block_to_db(
        &self,
        source_ip: &str,
        ip_version: u8,
        playbook_id: i64,
        expires_at: &str,
    ) -> Result<i64, Error> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO soar_block_rules (source_ip, playbook_id, expires_at) VALUES (?1, ?2, ?3)",
            params![source_ip, playbook_id, expires_at],
        )?;
        let soar_block_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT OR IGNORE INTO acl_rules (ip_version, direction, list_type, ip_address, port) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip_version, "source", "blacklist", source_ip, 0i64],
        )?;
        tx.commit()?;
        Ok(soar_block_id)
    }

    /// Clear a SOAR-driven block: remove the `acl_rules` entry and mark
    /// the `soar_block_rules` row as unblocked in one transaction.
    /// Callers handle eBPF unblock separately.
    fn commit_soar_unblock_to_db(&self, soar_block_id: i64, ip_version: u8, source_ip: &str) -> Result<(), Error> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM acl_rules WHERE ip_version = ?1 AND direction = ?2 AND list_type = ?3 AND ip_address = ?4 AND port = ?5",
            params![ip_version, "source", "blacklist", source_ip, 0i64],
        )?;
        tx.execute(
            "UPDATE soar_block_rules SET unblocked_at = datetime('now') WHERE id = ?1",
            params![soar_block_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;
    use crate::interface::port::db_admin::DbAdminRepo;

    /// Happy path. Verifies `commit_soar_block_to_db` writes both
    /// `soar_block_rules` and `acl_rules` atomically.
    #[test]
    fn test_commit_soar_block_happy_path() {
        let db = test_db();

        // Seed a playbook so the foreign-key-ish playbook_id refers to something real.
        let pb_id = db
            .insert_playbook("test_pb", "threat_detected", Some(0.9), None, None, 300)
            .unwrap();

        let soar_block_id = db
            .commit_soar_block_to_db("10.0.0.99", 4, pb_id, "2099-01-01 00:00:00")
            .unwrap();
        assert!(soar_block_id > 0);

        // soar_block_rules has the row
        let active = db.list_active_soar_blocks().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].1, "10.0.0.99");

        // acl_rules has the matching row
        let rules = db.list_acl_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].3, "10.0.0.99");
    }

    /// Verifies `commit_soar_unblock_to_db` removes the ACL row and marks
    /// the SOAR row as unblocked in one transaction.
    #[test]
    fn test_commit_soar_unblock_clears_both_tables() {
        let db = test_db();
        let pb_id = db
            .insert_playbook("test_pb", "threat_detected", Some(0.9), None, None, 300)
            .unwrap();
        let soar_block_id = db
            .commit_soar_block_to_db("10.0.0.99", 4, pb_id, "2099-01-01 00:00:00")
            .unwrap();

        db.commit_soar_unblock_to_db(soar_block_id, 4, "10.0.0.99").unwrap();

        // acl_rules row gone
        assert!(db.list_acl_rules().unwrap().is_empty());
        // soar_block_rules row no longer in "active" view (unblocked_at is set)
        assert!(db.list_active_soar_blocks().unwrap().is_empty());
    }
}
