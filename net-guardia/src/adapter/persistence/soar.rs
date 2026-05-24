use async_trait::async_trait;
use rusqlite::{Transaction, params};

use super::Database;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::response::defaults::{DEFAULT_PLAYBOOKS, DefaultPlaybook};
use crate::interface::response::playbook_data::{
    ActionInput, ActionView, ActiveBlockView, ConditionView, CreateConditionInput, CreatePlaybookInput, ExecutionView,
    PendingUnblock, PlaybookView, UpdatePlaybookInput,
};
use crate::interface::response::soar::{PlaybookRepo, SoarBlockRepo};

struct PlaybookActionRow {
    pb_id: i64,
    name: String,
    enabled: bool,
    trigger_event: String,
    condition_threshold: Option<f64>,
    condition_count: Option<i64>,
    condition_window_secs: Option<i64>,
    cooldown_secs: i64,
    action_id: Option<i64>,
    action_order: Option<i64>,
    action_type: Option<String>,
    action_params: Option<String>,
}

fn parse_persisted_json(row_id: i64, column: &str, raw: &str) -> Result<serde_json::Value, Error> {
    let parsed = serde_json::from_str(raw)
        .map_err(|err| DatabaseError::PersistedJsonInvalid(row_id, column.to_string(), err))?;
    Ok(parsed)
}

impl Database {
    async fn list_playbooks_with_actions(&self) -> Result<Vec<PlaybookActionRow>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT p.id, p.name, p.enabled, p.trigger_event, p.condition_threshold, \
                            p.condition_count, p.condition_window_secs, p.cooldown_secs, \
                            a.id, a.action_order, a.action_type, a.params \
                     FROM playbooks p \
                     LEFT JOIN playbook_actions a ON a.playbook_id = p.id \
                     ORDER BY p.id, a.action_order",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok(PlaybookActionRow {
                        pb_id: row.get::<_, i64>(0)?,
                        name: row.get::<_, String>(1)?,
                        enabled: row.get::<_, bool>(2)?,
                        trigger_event: row.get::<_, String>(3)?,
                        condition_threshold: row.get::<_, Option<f64>>(4)?,
                        condition_count: row.get::<_, Option<i64>>(5)?,
                        condition_window_secs: row.get::<_, Option<i64>>(6)?,
                        cooldown_secs: row.get::<_, i64>(7)?,
                        action_id: row.get::<_, Option<i64>>(8)?,
                        action_order: row.get::<_, Option<i64>>(9)?,
                        action_type: row.get::<_, Option<String>>(10)?,
                        action_params: row.get::<_, Option<String>>(11)?,
                    })
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }

    pub async fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let rows = conn.execute(
                    "UPDATE playbooks SET enabled = ?2, updated_at = datetime('now') WHERE id = ?1",
                    params![id, enabled as i32],
                )?;
                Ok(rows > 0)
            })
            .await
    }

    pub async fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let rows = conn.execute("DELETE FROM playbooks WHERE id = ?1", params![id])?;
                Ok(rows > 0)
            })
            .await
    }

    async fn list_all_playbook_conditions(&self) -> Result<Vec<(i64, ConditionView)>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, playbook_id, condition_type, operator, value, value2 \
                     FROM playbook_conditions ORDER BY playbook_id, id",
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(1)?,
                        ConditionView {
                            id: row.get::<_, i64>(0)?,
                            condition_type: row.get::<_, String>(2)?,
                            operator: row.get::<_, String>(3)?,
                            value: row.get::<_, String>(4)?,
                            value2: row.get::<_, Option<String>>(5)?,
                        },
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
    }

    pub async fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error> {
        let source_ip = source_ip.map(str::to_string);
        let trigger_event = trigger_event.to_string();
        let actions_json = actions_json.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO soar_executions (playbook_id, source_ip, trigger_event, actions_executed) VALUES (?1, ?2, ?3, ?4)",
                    params![playbook_id, source_ip, trigger_event, actions_json],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error> {
        self.pool
            .conn_and_then(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, playbook_id, source_ip, trigger_event, actions_executed, executed_at FROM soar_executions ORDER BY executed_at DESC LIMIT ?1"
                )?;
                let mut rows = stmt.query(params![limit])?;
                let mut result = Vec::new();
                while let Some(row) = rows.next()? {
                    let actions_str: String = row.get(4)?;
                    let id = row.get::<_, i64>(0)?;
                    result.push(ExecutionView {
                        id,
                        playbook_id: row.get::<_, i64>(1)?,
                        source_ip: row.get::<_, Option<String>>(2)?,
                        trigger_event: row.get::<_, String>(3)?,
                        actions_executed: parse_persisted_json(id, "soar_executions.actions_executed", &actions_str)?,
                        created_at: row.get::<_, String>(5)?,
                    });
                }
                Ok(result)
            })
            .await
    }

    pub async fn seed_default_playbooks(&self) -> Result<(), Error> {
        self.pool
            .conn_mut_and_then(move |conn| {
                let count: i64 = conn.query_row("SELECT COUNT(*) FROM playbooks", [], |row| row.get(0))?;
                if count > 0 {
                    return Ok(());
                }

                let tx = conn.transaction()?;
                seed_default_playbooks_tx(&tx, DEFAULT_PLAYBOOKS)?;
                tx.commit()?;
                Ok(())
            })
            .await
    }
}

fn seed_default_playbooks_tx(tx: &Transaction<'_>, defaults: &[DefaultPlaybook]) -> rusqlite::Result<()> {
    for def in defaults {
        tx.execute(
            "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![def.name, def.trigger_event, def.threshold, def.count, def.window, def.cooldown],
        )?;
        let playbook_id = tx.last_insert_rowid();
        for action in def.actions {
            tx.execute(
                "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                params![playbook_id, action.order, action.action_type, action.params],
            )?;
        }
        for condition in def.conditions {
            tx.execute(
                "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    playbook_id,
                    condition.condition_type,
                    condition.operator,
                    condition.value,
                    condition.value2
                ],
            )?;
        }
    }
    Ok(())
}

#[async_trait]
impl PlaybookRepo for Database {
    async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error> {
        let rows = self.list_playbooks_with_actions().await?;
        let mut result: Vec<PlaybookView> = Vec::new();
        for row in rows {
            if result.last().is_none_or(|playbook| playbook.id != row.pb_id) {
                result.push(PlaybookView {
                    id: row.pb_id,
                    name: row.name,
                    enabled: row.enabled,
                    trigger_event: row.trigger_event,
                    condition_threshold: row.condition_threshold,
                    condition_count: row.condition_count,
                    condition_window_secs: row.condition_window_secs,
                    cooldown_secs: row.cooldown_secs,
                    actions: Vec::new(),
                    conditions: Vec::new(),
                });
            }
            if let (Some(aid), Some(order), Some(atype), Some(params_str)) =
                (row.action_id, row.action_order, row.action_type, row.action_params)
                && let Some(pb) = result.last_mut()
            {
                pb.actions.push(ActionView {
                    id: aid,
                    action_order: order,
                    action_type: atype,
                    params: parse_persisted_json(aid, "playbook_actions.params", &params_str)?,
                });
            }
        }

        let cond_rows = self.list_all_playbook_conditions().await?;
        let mut cond_rows = cond_rows.into_iter().peekable();
        for pb in &mut result {
            while cond_rows.peek().is_some_and(|(pb_id, _)| *pb_id < pb.id) {
                cond_rows.next();
            }
            while cond_rows.peek().is_some_and(|(pb_id, _)| *pb_id == pb.id) {
                if let Some((_, cond)) = cond_rows.next() {
                    pb.conditions.push(cond);
                }
            }
        }
        Ok(result)
    }

    async fn insert_playbook_atomic(
        &self,
        input: &CreatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<i64, Error> {
        let input = input.clone();
        let actions = actions.to_vec();
        let conditions = conditions.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![input.name, input.trigger_event, input.condition_threshold, input.condition_count, input.condition_window_secs, input.cooldown_secs],
                )?;
                let playbook_id = tx.last_insert_rowid();
                for a in actions {
                    tx.execute(
                        "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                        params![playbook_id, a.action_order, a.action_type, a.params_json],
                    )?;
                }
                for c in conditions {
                    tx.execute(
                        "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![playbook_id, c.condition_type, c.operator, c.value, c.value2.as_deref()],
                    )?;
                }
                tx.commit()?;
                Ok(playbook_id)
            })
            .await
    }

    async fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        self.update_playbook_enabled(id, enabled).await
    }

    async fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<bool, Error> {
        let row = row.clone();
        let actions = actions.to_vec();
        let conditions = conditions.to_vec();
        self.pool
            .conn_mut_and_then(move |conn| {
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
                for a in actions {
                    tx.execute(
                        "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                        params![id, a.action_order, a.action_type, a.params_json],
                    )?;
                }
                for c in conditions {
                    tx.execute(
                        "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, c.condition_type, c.operator, c.value, c.value2.as_deref()],
                    )?;
                }
                tx.commit()?;
                Ok(true)
            })
            .await
    }

    async fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        self.delete_playbook(id).await
    }
}

#[async_trait]
impl SoarBlockRepo for Database {
    async fn count_active_soar_blocks(&self) -> Result<u32, Error> {
        self.count_active_soar_blocks().await
    }

    async fn list_active_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.list_active_soar_blocks().await
    }

    async fn find_soar_block_by_id(&self, id: i64) -> Result<Option<ActiveBlockView>, Error> {
        self.find_soar_block_by_id(id).await
    }

    async fn list_expired_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.list_expired_soar_blocks().await
    }

    async fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error> {
        self.list_pending_unblocks().await
    }

    async fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error> {
        self.list_soar_executions(limit).await
    }

    async fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error> {
        self.insert_pending_unblock(source_ip).await
    }

    async fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error> {
        self.insert_soar_execution(playbook_id, source_ip, trigger_event, actions_json)
            .await
    }

    async fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        self.mark_soar_block_unblocked(id).await
    }

    async fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error> {
        self.increment_pending_unblock_retry(id).await
    }

    async fn mark_pending_unblock_exhausted(&self, id: i64, last_error: &str) -> Result<(), Error> {
        self.mark_pending_unblock_exhausted(id, last_error).await
    }

    async fn delete_pending_unblock(&self, id: i64) -> Result<(), Error> {
        self.delete_pending_unblock(id).await
    }

    async fn commit_soar_block_to_db(
        &self,
        source_ip: &str,
        ip_version: IpVersion,
        playbook_id: i64,
        expires_at: &str,
    ) -> Result<i64, Error> {
        self.commit_soar_block_to_db(source_ip, ip_version, playbook_id, expires_at)
            .await
    }

    async fn commit_soar_unblock_to_db(
        &self,
        soar_block_id: i64,
        ip_version: IpVersion,
        source_ip: &str,
    ) -> Result<(), Error> {
        self.commit_soar_unblock_to_db(soar_block_id, ip_version, source_ip)
            .await
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;
    use crate::domain::response::defaults::{DefaultAction, DefaultCondition};

    #[tokio::test]
    async fn seed_default_playbooks_populates_all_defaults() {
        let db = Database::new(":memory:").await.expect("database");

        db.seed_default_playbooks().await.expect("seed defaults");

        let playbooks = db.list_playbooks().await.expect("list playbooks");
        assert_eq!(playbooks.len(), DEFAULT_PLAYBOOKS.len());
        for expected in DEFAULT_PLAYBOOKS {
            let actual = playbooks
                .iter()
                .find(|playbook| playbook.name == expected.name)
                .expect("default playbook exists");
            assert_eq!(actual.actions.len(), expected.actions.len());
            assert_eq!(actual.conditions.len(), expected.conditions.len());
        }
    }

    #[tokio::test]
    async fn seed_default_playbooks_rolls_back_partial_defaults_on_insert_failure() {
        static DUPLICATE_CONDITIONS: &[DefaultCondition] = &[
            DefaultCondition {
                condition_type: "threshold",
                operator: ">=",
                value: "0.7",
                value2: None,
            },
            DefaultCondition {
                condition_type: "threshold",
                operator: ">=",
                value: "0.8",
                value2: None,
            },
        ];
        static ACTIONS: &[DefaultAction] = &[DefaultAction {
            order: 1,
            action_type: "log",
            params: "{}",
        }];
        static DEFAULTS: &[DefaultPlaybook] = &[DefaultPlaybook {
            name: "bad_default",
            trigger_event: "port_scan",
            threshold: Some(0.7),
            count: None,
            window: None,
            cooldown: 300,
            actions: ACTIONS,
            conditions: DUPLICATE_CONDITIONS,
        }];

        let db = Database::new(":memory:").await.expect("database");
        let result = db
            .pool
            .conn_mut_and_then(move |conn| {
                let tx = conn.transaction()?;
                let result = seed_default_playbooks_tx(&tx, DEFAULTS);
                if result.is_ok() {
                    tx.commit()?;
                }
                result.map_err(Error::from)
            })
            .await;

        assert!(result.is_err());
        let playbook_count: i64 = db
            .pool
            .conn_and_then(move |conn| {
                Ok::<i64, Error>(conn.query_row("SELECT COUNT(*) FROM playbooks", [], |row| row.get(0))?)
            })
            .await
            .expect("count playbooks");
        assert_eq!(playbook_count, 0);
    }
}
