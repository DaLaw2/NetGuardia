use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::response::playbook_data::UpdatePlaybookInput;
use crate::interface::port::soar::{PlaybookRow, SoarExecutionRow, SoarRepo};

impl Database {
    pub fn insert_playbook(
        &self,
        name: &str,
        trigger_event: &str,
        threshold: Option<f64>,
        count: Option<i64>,
        window: Option<i64>,
        cooldown: i64,
    ) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, trigger_event, threshold, count, window, cooldown],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn insert_playbook_action(
        &self,
        playbook_id: i64,
        action_order: i64,
        action_type: &str,
        params_json: &str,
    ) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
            params![playbook_id, action_order, action_type, params_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Load all playbooks with their actions in a single JOIN query (avoids N+1).
    /// Returns Vec of (playbook fields..., action fields...).
    pub fn list_playbooks_with_actions(
        &self,
    ) -> Result<
        Vec<(
            i64,
            String,
            bool,
            String,
            Option<f64>,
            Option<i64>,
            Option<i64>,
            i64,
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<String>,
        )>,
        Error,
    > {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.name, p.enabled, p.trigger_event, p.condition_threshold, \
                    p.condition_count, p.condition_window_secs, p.cooldown_secs, \
                    a.id, a.action_order, a.action_type, a.params \
             FROM playbooks p \
             LEFT JOIN playbook_actions a ON a.playbook_id = p.id \
             ORDER BY p.id, a.action_order",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<f64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        let conn = self.conn()?;
        let rows = conn.execute(
            "UPDATE playbooks SET enabled = ?2, updated_at = datetime('now') WHERE id = ?1",
            params![id, enabled as i32],
        )?;
        Ok(rows > 0)
    }

    pub fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        let conn = self.conn()?;
        let rows = conn.execute("DELETE FROM playbooks WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    pub fn insert_playbook_condition(
        &self,
        playbook_id: i64,
        condition_type: &str,
        operator: &str,
        value: &str,
        value2: Option<&str>,
    ) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![playbook_id, condition_type, operator, value, value2],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_all_playbook_conditions(
        &self,
    ) -> Result<Vec<(i64, i64, String, String, String, Option<String>)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, playbook_id, condition_type, operator, value, value2 \
             FROM playbook_conditions ORDER BY playbook_id, id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO soar_executions (playbook_id, source_ip, trigger_event, actions_executed) VALUES (?1, ?2, ?3, ?4)",
            params![playbook_id, source_ip, trigger_event, actions_json],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn list_soar_executions(
        &self,
        limit: i64,
    ) -> Result<Vec<(i64, i64, Option<String>, String, String, String)>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, playbook_id, source_ip, trigger_event, actions_executed, executed_at FROM soar_executions ORDER BY executed_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    pub fn seed_default_playbooks(&self) -> Result<(), Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM playbooks", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(());
        }
        drop(conn);

        // 1. brute_force_block: brute_force, count 5 in 60s → block_ip(3600s) + send_telegram + log
        let pb1 = self.insert_playbook("brute_force_block", "brute_force", None, Some(5), Some(60), 600)?;
        self.insert_playbook_action(pb1, 1, "block_ip", r#"{"ttl_secs": 3600}"#)?;
        self.insert_playbook_action(pb1, 2, "send_telegram", "{}")?;
        self.insert_playbook_action(pb1, 3, "log", r#"{"level": "warn"}"#)?;
        self.insert_playbook_condition(pb1, "frequency", ">=", "5", Some("60"))?;

        // 2. port_scan_alert: port_scan, threshold 0.7 → send_telegram + log (no block)
        let pb2 = self.insert_playbook("port_scan_alert", "port_scan", Some(0.7), None, None, 300)?;
        self.insert_playbook_action(pb2, 1, "send_telegram", "{}")?;
        self.insert_playbook_action(pb2, 2, "log", r#"{"level": "warn"}"#)?;
        self.insert_playbook_condition(pb2, "threshold", ">=", "0.7", None)?;

        // 3. fusion_c2_multi_source_block — C2 beacon observed by ≥2 sources
        //    (e.g. Suricata trojan-activity + Beaconing CV + ML c2 class) is
        //    the highest-precision fusion signal we ship. Block for 1h and
        //    notify, no solo-source threshold so single-source C2 hits still
        //    require the solo playbook below to act.
        let pb3 = self.insert_playbook("fusion_c2_multi_source_block", "c2_beacon", None, None, None, 600)?;
        self.insert_playbook_action(pb3, 1, "block_ip", r#"{"ttl_secs": 3600}"#)?;
        self.insert_playbook_action(pb3, 2, "send_telegram", "{}")?;
        self.insert_playbook_action(pb3, 3, "log", r#"{"level": "warn"}"#)?;
        self.insert_playbook_condition(pb3, "multi_source_min", ">=", "2", None)?;

        // 4. fusion_c2_suricata_solo_high_block — the escape hatch for
        //    Suricata signature hits with very high confidence (>=0.95).
        //    Lets known-good rules fire without waiting for agreement from a
        //    second source, matching how analysts intuitively treat a
        //    signature "dead-on" match.
        let pb4 = self.insert_playbook("fusion_c2_suricata_solo_high_block", "c2_beacon", None, None, None, 600)?;
        self.insert_playbook_action(pb4, 1, "block_ip", r#"{"ttl_secs": 3600}"#)?;
        self.insert_playbook_action(pb4, 2, "send_telegram", "{}")?;
        self.insert_playbook_action(pb4, 3, "log", r#"{"level": "warn"}"#)?;
        self.insert_playbook_condition(pb4, "single_source_high", "==", "Suricata", Some("0.95"))?;

        Ok(())
    }
}

impl SoarRepo for Database {
    fn list_playbooks_with_actions(&self) -> Result<Vec<PlaybookRow>, Error> {
        self.list_playbooks_with_actions()
    }

    fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        self.update_playbook_enabled(id, enabled)
    }

    fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        self.delete_playbook(id)
    }

    fn seed_default_playbooks(&self) -> Result<(), Error> {
        self.seed_default_playbooks()
    }

    fn list_all_playbook_conditions(&self) -> Result<Vec<(i64, i64, String, String, String, Option<String>)>, Error> {
        self.list_all_playbook_conditions()
    }

    fn count_active_soar_blocks(&self) -> Result<u32, Error> {
        self.count_active_soar_blocks()
    }

    fn list_active_soar_blocks(&self) -> Result<Vec<(i64, String, i64, String)>, Error> {
        self.list_active_soar_blocks()
    }

    fn find_soar_block_by_id(&self, id: i64) -> Result<Option<(i64, String, i64, String)>, Error> {
        self.find_soar_block_by_id(id)
    }

    fn list_expired_soar_blocks(&self) -> Result<Vec<(i64, String, i64)>, Error> {
        self.list_expired_soar_blocks()
    }

    fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        self.mark_soar_block_unblocked(id)
    }

    fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error> {
        self.insert_pending_unblock(source_ip)
    }

    fn list_pending_unblocks(&self) -> Result<Vec<(i64, String, i64)>, Error> {
        self.list_pending_unblocks()
    }

    fn delete_pending_unblock(&self, id: i64) -> Result<(), Error> {
        self.delete_pending_unblock(id)
    }

    fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error> {
        self.increment_pending_unblock_retry(id)
    }

    fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error> {
        self.insert_soar_execution(playbook_id, source_ip, trigger_event, actions_json)
    }

    fn list_soar_executions(&self, limit: i64) -> Result<Vec<SoarExecutionRow>, Error> {
        self.list_soar_executions(limit)
    }

    fn insert_playbook_atomic(
        &self,
        name: &str,
        trigger_event: &str,
        threshold: Option<f64>,
        count: Option<i64>,
        window: Option<i64>,
        cooldown: i64,
        actions: &[(i64, String, String)],
        conditions: &[(String, String, String, Option<String>)],
    ) -> Result<i64, Error> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, trigger_event, threshold, count, window, cooldown],
        )?;
        let playbook_id = tx.last_insert_rowid();
        for (action_order, action_type, params_json) in actions {
            tx.execute(
                "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                params![playbook_id, action_order, action_type, params_json],
            )?;
        }
        for (condition_type, operator, value, value2) in conditions {
            tx.execute(
                "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![playbook_id, condition_type, operator, value, value2.as_deref()],
            )?;
        }
        tx.commit()?;
        Ok(playbook_id)
    }

    fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookInput,
        actions: &[(i64, String, String)],
        conditions: &[(String, String, String, Option<String>)],
    ) -> Result<bool, Error> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let rows_updated = tx.execute(
            "UPDATE playbooks SET name = ?2, trigger_event = ?3, condition_threshold = ?4, \
             condition_count = ?5, condition_window_secs = ?6, cooldown_secs = ?7, \
             updated_at = datetime('now') WHERE id = ?1",
            params![
                id,
                row.name,
                row.trigger_event,
                row.condition_threshold,
                row.condition_count,
                row.condition_window_secs,
                row.cooldown_secs
            ],
        )?;
        if rows_updated == 0 {
            return Ok(false);
        }
        tx.execute("DELETE FROM playbook_actions WHERE playbook_id = ?1", params![id])?;
        tx.execute("DELETE FROM playbook_conditions WHERE playbook_id = ?1", params![id])?;
        for (action_order, action_type, params_json) in actions {
            tx.execute(
                "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                params![id, action_order, action_type, params_json],
            )?;
        }
        for (condition_type, operator, value, value2) in conditions {
            tx.execute(
                "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, condition_type, operator, value, value2.as_deref()],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::test_db;

    /// Verifies `insert_playbook_atomic` writes playbook + actions + conditions
    /// atomically.
    #[test]
    fn test_insert_playbook_atomic_writes_all_three_tables() {
        use crate::interface::port::soar::SoarRepo;

        let db = test_db();
        let actions = vec![(1i64, "block_ip".to_string(), "{}".to_string())];
        let conditions = vec![("threshold".to_string(), ">=".to_string(), "0.8".to_string(), None)];
        let id = db
            .insert_playbook_atomic("atom_pb", "threat", Some(0.8), None, None, 300, &actions, &conditions)
            .unwrap();
        assert!(id > 0);
        let loaded = db.list_playbooks_with_actions().unwrap();
        assert!(!loaded.is_empty());
        let cond_rows = db.list_all_playbook_conditions().unwrap();
        assert_eq!(cond_rows.len(), 1);
    }
}
