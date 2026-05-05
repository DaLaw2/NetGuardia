use std::sync::Arc;

use crate::core::response::engine::SoarEngine;
use crate::domain::common::error::Error;
use crate::domain::response::error::SoarError;
use crate::domain::response::playbook_data::{
    ActionInput, ActiveBlockView, CreatePlaybookInput, ExecutionView, PlaybookView, UpdatePlaybookInput,
};
use crate::interface::access_control::AccessControlPort;
use crate::interface::app_repo::AppRepo;
use crate::utils::ip_address::ip_version_from_str;

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

    pub async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error> {
        self.db.list_playbooks().await
    }

    pub async fn create_playbook(&self, input: &CreatePlaybookInput) -> Result<i64, Error> {
        // Single atomic insert (playbook + actions + conditions).
        let actions: Vec<ActionInput> = input
            .actions
            .iter()
            .enumerate()
            .map(|(i, (ty, params))| ActionInput {
                action_order: (i + 1) as i64,
                action_type: ty.clone(),
                params_json: params.clone(),
            })
            .collect();
        let playbook_id = self
            .db
            .insert_playbook_atomic(input, &actions, &input.conditions)
            .await?;
        self.soar_engine.reload_cache().await?;
        Ok(playbook_id)
    }

    pub async fn update_playbook(&self, id: i64, input: &CreatePlaybookInput) -> Result<bool, Error> {
        let row = UpdatePlaybookInput {
            name: input.name.clone(),
            trigger_event: input.trigger_event.clone(),
            condition_threshold: input.condition_threshold,
            condition_count: input.condition_count,
            condition_window_secs: input.condition_window_secs,
            cooldown_secs: input.cooldown_secs,
        };
        // Single atomic update (playbook metadata + replace actions/conditions).
        let actions: Vec<ActionInput> = input
            .actions
            .iter()
            .enumerate()
            .map(|(i, (ty, params))| ActionInput {
                action_order: (i + 1) as i64,
                action_type: ty.clone(),
                params_json: params.clone(),
            })
            .collect();
        let updated = self
            .db
            .update_playbook_atomic(id, &row, &actions, &input.conditions)
            .await?;
        if !updated {
            return Ok(false);
        }
        self.soar_engine.reload_cache().await?;
        Ok(true)
    }

    pub async fn toggle_playbook(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        let updated = self.db.update_playbook_enabled(id, enabled).await?;
        if updated {
            self.soar_engine.reload_cache().await?;
        }
        Ok(updated)
    }

    pub async fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        let deleted = self.db.delete_playbook(id).await?;
        if deleted {
            self.soar_engine.reload_cache().await?;
        }
        Ok(deleted)
    }

    pub async fn list_active_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.db.list_active_soar_blocks().await
    }

    /// Manually unblock an IP: remove from eBPF, atomically clear both DB
    /// tables via `DbAdminRepo::commit_soar_unblock_to_db` (tx-3), decrement
    /// counter.
    pub async fn manual_unblock(&self, id: i64) -> Result<(), Error> {
        // Look up the block to get source_ip
        let block = self
            .db
            .find_soar_block_by_id(id)
            .await?
            .ok_or_else(|| SoarError::UnblockRuleNotFound(id))?;
        let source_ip = &block.source_ip;

        // Remove from eBPF ACL
        self.access_control.unblock_ip(source_ip)?;

        // Atomically drop acl_rules entry AND mark soar_block_rules
        // unblocked in one transaction.
        let ip_version = ip_version_from_str(source_ip);
        self.db.commit_soar_unblock_to_db(id, ip_version, source_ip).await?;

        // Decrement active block counter
        self.soar_engine.decrement_block_count();

        Ok(())
    }

    pub async fn list_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error> {
        self.db.list_soar_executions(limit).await
    }

    pub async fn list_whitelist(&self) -> Result<Vec<String>, Error> {
        self.db.list_admin_whitelist().await
    }

    pub async fn add_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.db.insert_admin_whitelist(ip).await?;
        self.soar_engine.reload_cache().await?;
        Ok(())
    }

    pub async fn remove_whitelist(&self, ip: &str) -> Result<(), Error> {
        self.db.delete_admin_whitelist(ip).await?;
        self.soar_engine.reload_cache().await?;
        Ok(())
    }
}
