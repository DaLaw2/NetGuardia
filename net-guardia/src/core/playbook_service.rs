use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde_json::Value;

use crate::core::soar::engine::SoarEngine;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::app_repo::AppRepo;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::soar::playbook_data::{
    ActionData, ActiveBlockData, ConditionData, CreatePlaybookInput, ExecutionData, PlaybookData, UpdatePlaybookRow,
};

/// Domain service for SOAR playbook CRUD operations.
/// Coordinates DB reads/writes, SOAR engine cache refresh, and eBPF unblock.
pub struct PlaybookService {
    db: Arc<dyn AppRepo>,
    soar_engine: Arc<SoarEngine>,
    access_control: Arc<dyn AccessControlPort>,
}

impl PlaybookService {
    pub fn new(db: Arc<dyn AppRepo>, soar_engine: Arc<SoarEngine>, access_control: Arc<dyn AccessControlPort>) -> Self {
        Self {
            db,
            soar_engine,
            access_control,
        }
    }

    pub fn list_playbooks(&self) -> Result<Vec<PlaybookData>, Error> {
        let rows = self.db.load_playbooks_with_actions()?;
        let mut result: Vec<PlaybookData> = Vec::new();

        for (
            pb_id,
            name,
            enabled,
            trigger_event,
            threshold,
            count,
            window,
            cooldown,
            action_id,
            action_order,
            action_type,
            action_params,
        ) in rows
        {
            // Find or create the playbook entry
            let pb = if let Some(last) = result.last_mut() {
                if last.id == pb_id {
                    last
                } else {
                    result.push(PlaybookData {
                        id: pb_id,
                        name,
                        enabled,
                        trigger_event,
                        condition_threshold: threshold,
                        condition_count: count,
                        condition_window_secs: window,
                        cooldown_secs: cooldown,
                        actions: Vec::new(),
                        conditions: Vec::new(),
                    });
                    // SAFETY: just pushed above, Vec cannot be empty
                    result.last_mut().unwrap_or_else(|| unreachable!())
                }
            } else {
                result.push(PlaybookData {
                    id: pb_id,
                    name,
                    enabled,
                    trigger_event,
                    condition_threshold: threshold,
                    condition_count: count,
                    condition_window_secs: window,
                    cooldown_secs: cooldown,
                    actions: Vec::new(),
                    conditions: Vec::new(),
                });
                // SAFETY: just pushed above, Vec cannot be empty
                result.last_mut().unwrap_or_else(|| unreachable!())
            };

            // Append action if present (LEFT JOIN may yield NULLs)
            if let (Some(aid), Some(order), Some(atype), Some(params_str)) =
                (action_id, action_order, action_type, action_params)
            {
                pb.actions.push(ActionData {
                    id: aid,
                    action_order: order,
                    action_type: atype,
                    params: serde_json::from_str(&params_str).unwrap_or(Value::Null),
                });
            }
        }

        // Load conditions and attach to playbooks
        let cond_rows = self.db.load_all_playbook_conditions()?;
        let mut cond_map: HashMap<i64, Vec<ConditionData>> = HashMap::new();
        for (cid, pb_id, ctype, operator, value, value2) in cond_rows {
            cond_map.entry(pb_id).or_default().push(ConditionData {
                id: cid,
                condition_type: ctype,
                operator,
                value,
                value2,
            });
        }
        for pb in &mut result {
            if let Some(conds) = cond_map.remove(&pb.id) {
                pb.conditions = conds;
            }
        }

        Ok(result)
    }

    pub fn create_playbook(&self, input: &CreatePlaybookInput) -> Result<i64, Error> {
        // Single atomic insert (playbook + actions + conditions).
        let actions: Vec<(i64, String, String)> = input
            .actions
            .iter()
            .enumerate()
            .map(|(i, (ty, params))| ((i + 1) as i64, ty.clone(), params.clone()))
            .collect();
        let conditions: Vec<(String, String, String, Option<String>)> = input
            .conditions
            .iter()
            .map(|c| {
                (
                    c.condition_type.clone(),
                    c.operator.clone(),
                    c.value.clone(),
                    c.value2.clone(),
                )
            })
            .collect();
        let playbook_id = self.db.insert_playbook_atomic(
            &input.name,
            &input.trigger_event,
            input.condition_threshold,
            input.condition_count,
            input.condition_window_secs,
            input.cooldown_secs,
            &actions,
            &conditions,
        )?;
        self.soar_engine.reload_cache()?;
        Ok(playbook_id)
    }

    pub fn update_playbook(&self, id: i64, input: &CreatePlaybookInput) -> Result<bool, Error> {
        let row = UpdatePlaybookRow {
            name: input.name.clone(),
            trigger_event: input.trigger_event.clone(),
            condition_threshold: input.condition_threshold,
            condition_count: input.condition_count,
            condition_window_secs: input.condition_window_secs,
            cooldown_secs: input.cooldown_secs,
        };
        // Single atomic update (playbook metadata + replace actions/conditions).
        let actions: Vec<(i64, String, String)> = input
            .actions
            .iter()
            .enumerate()
            .map(|(i, (ty, params))| ((i + 1) as i64, ty.clone(), params.clone()))
            .collect();
        let conditions: Vec<(String, String, String, Option<String>)> = input
            .conditions
            .iter()
            .map(|c| {
                (
                    c.condition_type.clone(),
                    c.operator.clone(),
                    c.value.clone(),
                    c.value2.clone(),
                )
            })
            .collect();
        let updated = self.db.update_playbook_atomic(id, &row, &actions, &conditions)?;
        if !updated {
            return Ok(false);
        }
        self.soar_engine.reload_cache()?;
        Ok(true)
    }

    pub fn toggle_playbook(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        let updated = self.db.update_playbook_enabled(id, enabled)?;
        if updated {
            self.soar_engine.reload_cache()?;
        }
        Ok(updated)
    }

    pub fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        let deleted = self.db.delete_playbook(id)?;
        if deleted {
            self.soar_engine.reload_cache()?;
        }
        Ok(deleted)
    }

    pub fn list_active_blocks(&self) -> Result<Vec<ActiveBlockData>, Error> {
        let blocks = self.db.get_active_soar_blocks()?;
        Ok(blocks
            .into_iter()
            .map(|(id, ip, pb_id, expires)| ActiveBlockData {
                id,
                source_ip: ip,
                playbook_id: pb_id,
                expires_at: expires,
            })
            .collect())
    }

    /// Manually unblock an IP: remove from eBPF, atomically clear both DB
    /// tables via `DbAdminRepo::commit_soar_unblock_to_db` (tx-3), decrement
    /// counter.
    pub async fn manual_unblock(&self, id: i64) -> Result<(), Error> {
        // Look up the block to get source_ip
        let block = self
            .db
            .get_soar_block_by_id(id)?
            .ok_or_else(|| SoarError::UnblockRuleNotFound(id))?;
        let source_ip = &block.1;

        // Remove from eBPF ACL
        self.access_control.unblock_ip(source_ip)?;

        // Atomically drop acl_rules entry AND mark soar_block_rules
        // unblocked in one transaction.
        let ip_version = ip_version_from_str(source_ip);
        self.db.commit_soar_unblock_to_db(id, ip_version, source_ip)?;

        // Decrement active block counter
        self.soar_engine.decrement_block_count();

        Ok(())
    }

    pub fn list_executions(&self, limit: i64) -> Result<Vec<ExecutionData>, Error> {
        let rows = self.db.list_soar_executions(limit)?;
        Ok(rows
            .into_iter()
            .map(
                |(id, pb_id, source_ip, trigger_event, actions, created_at)| ExecutionData {
                    id,
                    playbook_id: pb_id,
                    source_ip,
                    trigger_event,
                    actions_executed: serde_json::from_str(&actions).unwrap_or(Value::Null),
                    created_at,
                },
            )
            .collect())
    }

    pub fn list_whitelist(&self) -> Result<Vec<String>, Error> {
        self.db.load_admin_whitelist()
    }

    pub fn add_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.db.insert_admin_whitelist(ip)?;
        self.soar_engine.reload_cache()?;
        Ok(())
    }

    pub fn remove_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.db.delete_admin_whitelist(ip)?;
        self.soar_engine.reload_cache()?;
        Ok(())
    }
}

/// Determine IP version from a string address using proper parsing.
pub fn ip_version_from_str(ip: &str) -> u8 {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => 4,
        Ok(IpAddr::V6(_)) => 6,
        Err(_) => {
            if ip.contains(':') {
                6
            } else {
                4
            }
        } // fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_version_from_str_ipv4() {
        assert_eq!(ip_version_from_str("1.2.3.4"), 4);
        assert_eq!(ip_version_from_str("192.168.1.1"), 4);
    }

    #[test]
    fn ip_version_from_str_ipv6() {
        assert_eq!(ip_version_from_str("::1"), 6);
        assert_eq!(ip_version_from_str("2001:db8::1"), 6);
    }

    #[test]
    fn ip_version_from_str_ipv4_mapped_ipv6() {
        // ::ffff:1.2.3.4 should be recognized as IPv6 (it is an IPv6 address)
        assert_eq!(ip_version_from_str("::ffff:1.2.3.4"), 6);
    }
}
