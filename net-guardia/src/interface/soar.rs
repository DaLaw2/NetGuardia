use crate::domain::common::error::Error;
use crate::domain::response::playbook_data::{
    ActionInput, ActiveBlockView, CreateConditionInput, CreatePlaybookInput, ExecutionView, PendingUnblock,
    PlaybookView, UpdatePlaybookInput,
};

/// Threat Response BC — SOAR aggregate repository.
///
/// Covers playbook CRUD, condition CRUD, block-rule lifecycle, pending-unblock
/// recovery queue, and the execution log. The settings (`soar_*`) and ACL
/// writes that block actions depend on live in `SettingRepo` and `AclRepo`
/// respectively; cross-aggregate atomicity is handled via
/// `DbAdminRepo::with_transaction` + `TxRepos`.
pub trait SoarRepo: Send + Sync {
    // --- Playbooks ---
    fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error>;
    fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error>;
    fn delete_playbook(&self, id: i64) -> Result<bool, Error>;
    fn seed_default_playbooks(&self) -> Result<(), Error>;

    // --- Block Rules ---
    fn count_active_soar_blocks(&self) -> Result<u32, Error>;
    fn list_active_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    fn find_soar_block_by_id(&self, id: i64) -> Result<Option<ActiveBlockView>, Error>;
    fn list_expired_soar_blocks(&self) -> Result<Vec<ActiveBlockView>, Error>;
    fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error>;

    // --- Pending Unblock Recovery ---
    fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error>;
    fn list_pending_unblocks(&self) -> Result<Vec<PendingUnblock>, Error>;
    fn delete_pending_unblock(&self, id: i64) -> Result<(), Error>;
    fn increment_pending_unblock_retry(&self, id: i64) -> Result<(), Error>;

    // --- Execution Log ---
    fn insert_soar_execution(
        &self,
        playbook_id: i64,
        source_ip: Option<&str>,
        trigger_event: &str,
        actions_json: &str,
    ) -> Result<i64, Error>;
    fn list_soar_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error>;

    // --- Intra-aggregate atomic operations ---

    /// Atomically create a playbook with its conditions and actions.
    /// All rows (playbook + conditions + actions) commit together; any error
    /// rolls back the whole insert. Returns the new playbook id.
    ///
    fn insert_playbook_atomic(
        &self,
        input: &CreatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<i64, Error>;

    fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookInput,
        actions: &[ActionInput],
        conditions: &[CreateConditionInput],
    ) -> Result<bool, Error>;
}
