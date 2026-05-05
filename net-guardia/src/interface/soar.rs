use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::domain::response::playbook_data::{
    ActionInput, ActiveBlockView, CreateConditionInput, CreatePlaybookInput, ExecutionView, PendingUnblock,
    PlaybookView, UpdatePlaybookInput,
};

/// Threat Response BC — SOAR aggregate repository.
///
/// Covers playbook CRUD, condition CRUD, block-rule lifecycle, pending-unblock
/// recovery queue, and the execution log. The settings (`soar_*`) and ACL
/// writes that block actions depend on live in `ConfigRepo` and `AclRepo`
/// respectively; cross-aggregate atomicity is handled via
/// `DbAdminRepo::with_transaction` + `TxRepos`.
#[async_trait]
pub trait SoarRepo: Send + Sync {
    // --- Playbooks ---
    async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error>;
    async fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error>;
    async fn delete_playbook(&self, id: i64) -> Result<bool, Error>;
    async fn seed_default_playbooks(&self) -> Result<(), Error>;

    // --- Block Rules ---
    async fn count_active_soar_blocks(&self) -> Result<u32, Error>;
    async fn list_active_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    async fn find_soar_block_by_id(&self, id: i64) -> Result<Option<ActiveBlockView>, Error>;
    async fn list_expired_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    async fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error>;

    // --- Pending Unblock Recovery ---
    async fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error>;
    async fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error>;
    async fn delete_pending_unblock(&self, id: i64) -> Result<(), Error>;
    async fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error>;

    // --- Execution Log ---
    async fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error>;
    async fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error>;

    // --- Intra-aggregate atomic operations ---

    /// Atomically create a playbook with its conditions and actions.
    /// All rows (playbook + conditions + actions) commit together; any error
    /// rolls back the whole insert. Returns the new playbook id.
    ///
    async fn insert_playbook_atomic(
        &self,
        input: &CreatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<i64, Error>;

    async fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<bool, Error>;
}
