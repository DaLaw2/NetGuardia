use std::collections::HashMap;

use async_trait::async_trait;
use rusqlite::params;
use serde_json::Value;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::response::defaults::DEFAULT_PLAYBOOKS;
use crate::domain::response::playbook_data::{
    ActionInput, ActionView, ActiveBlockView, ConditionView, CreateConditionInput, CreatePlaybookInput, ExecutionView,
    PendingUnblock, PlaybookView, UpdatePlaybookInput,
};
use crate::interface::soar::SoarRepo;

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

impl Database {
    pub async fn insert_playbook(
        &self,
        name: &str,
        trigger_event: &str,
        threshold: Option<f64>,
        count: Option<i64>,
        window: Option<i64>,
        cooldown: i64,
    ) -> Result<i64, Error> {
        let name = name.to_string();
        let trigger_event = trigger_event.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO playbooks (name, trigger_event, condition_threshold, condition_count, condition_window_secs, cooldown_secs) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![name, trigger_event, threshold, count, window, cooldown],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

    pub async fn insert_playbook_action(
        &self,
        playbook_id: i64,
        action_order: i64,
        action_type: &str,
        params_json: &str,
    ) -> Result<i64, Error> {
        let action_type = action_type.to_string();
        let params_json = params_json.to_string();
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO playbook_actions (playbook_id, action_order, action_type, params) VALUES (?1, ?2, ?3, ?4)",
                    params![playbook_id, action_order, action_type, params_json],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
    }

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
                let mut result = Vec::new();
                for row in rows {
                    result.push(row?);
                }
                Ok(result)
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

    pub async fn insert_playbook_condition(
        &self,
        playbook_id: i64,
        condition_type: &str,
        operator: &str,
        value: &str,
        value2: Option<&str>,
    ) -> Result<i64, Error> {
        let condition_type = condition_type.to_string();
        let operator = operator.to_string();
        let value = value.to_string();
        let value2 = value2.map(str::to_string);
        self.pool
            .conn_and_then(move |conn| {
                conn.execute(
                    "INSERT INTO playbook_conditions (playbook_id, condition_type, operator, value, value2) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![playbook_id, condition_type, operator, value, value2],
                )?;
                Ok(conn.last_insert_rowid())
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
                let mut result = Vec::new();
                for row in rows {
                    result.push(row?);
                }
                Ok(result)
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
                let rows = stmt.query_map(params![limit], |row| {
                    let actions_str: String = row.get(4)?;
                    Ok(ExecutionView {
                        id: row.get::<_, i64>(0)?,
                        playbook_id: row.get::<_, i64>(1)?,
                        source_ip: row.get::<_, Option<String>>(2)?,
                        trigger_event: row.get::<_, String>(3)?,
                        actions_executed: serde_json::from_str(&actions_str).unwrap_or(Value::Null),
                        created_at: row.get::<_, String>(5)?,
                    })
                })?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row?);
                }
                Ok(result)
            })
            .await
    }

    pub async fn seed_default_playbooks(&self) -> Result<(), Error> {
        let count: i64 = self
            .pool
            .conn_and_then(move |conn| {
                Ok::<i64, Error>(conn.query_row("SELECT COUNT(*) FROM playbooks", [], |row| row.get(0))?)
            })
            .await?;
        if count > 0 {
            return Ok(());
        }
        for def in DEFAULT_PLAYBOOKS {
            let pb_id = self
                .insert_playbook(
                    def.name,
                    def.trigger_event,
                    def.threshold,
                    def.count,
                    def.window,
                    def.cooldown,
                )
                .await?;
            for action in def.actions {
                self.insert_playbook_action(pb_id, action.order, action.action_type, action.params)
                    .await?;
            }
            for cond in def.conditions {
                self.insert_playbook_condition(pb_id, cond.condition_type, cond.operator, cond.value, cond.value2)
                    .await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SoarRepo for Database {
    async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error> {
        let rows = self.list_playbooks_with_actions().await?;
        let mut result: Vec<PlaybookView> = Vec::new();
        for row in rows {
            let pb = if let Some(position) = result.iter().position(|p| p.id == row.pb_id) {
                &mut result[position]
            } else {
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
                result.last_mut().unwrap_or_else(|| unreachable!())
            };
            if let (Some(aid), Some(order), Some(atype), Some(params_str)) =
                (row.action_id, row.action_order, row.action_type, row.action_params)
            {
                pb.actions.push(ActionView {
                    id: aid,
                    action_order: order,
                    action_type: atype,
                    params: serde_json::from_str(&params_str).unwrap_or(Value::Null),
                });
            }
        }

        let cond_rows = self.list_all_playbook_conditions().await?;
        let mut cond_map: HashMap<i64, Vec<ConditionView>> = HashMap::new();
        for (pb_id, cond) in cond_rows {
            cond_map.entry(pb_id).or_default().push(cond);
        }
        for pb in &mut result {
            if let Some(conds) = cond_map.remove(&pb.id) {
                pb.conditions = conds;
            }
        }
        Ok(result)
    }

    async fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        self.update_playbook_enabled(id, enabled).await
    }

    async fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        self.delete_playbook(id).await
    }

    async fn seed_default_playbooks(&self) -> Result<(), Error> {
        self.seed_default_playbooks().await
    }

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

    async fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error> {
        self.mark_soar_block_unblocked(id).await
    }

    async fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error> {
        self.insert_pending_unblock(source_ip).await
    }

    async fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error> {
        self.list_pending_unblocks().await
    }

    async fn delete_pending_unblock(&self, id: i64) -> Result<(), Error> {
        self.delete_pending_unblock(id).await
    }

    async fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error> {
        self.increment_pending_unblock_retry(id).await
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

    async fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error> {
        self.list_soar_executions(limit).await
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
}
