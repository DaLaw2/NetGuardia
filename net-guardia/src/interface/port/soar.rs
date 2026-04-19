use crate::model::error::Error;
use crate::model::soar::playbook_data::UpdatePlaybookRow;

/// Type alias for playbook+action JOIN rows.
/// (id, name, enabled, trigger_event, threshold, count, window, cooldown, action_id, action_order, action_type, params)
#[allow(clippy::type_complexity)]
pub type PlaybookRow = (
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
);

/// Type alias for SOAR execution log rows.
/// (id, playbook_id, source_ip, trigger_event, actions_executed, executed_at)
#[allow(clippy::type_complexity)]
pub type SoarExecutionRow = (i64, i64, Option<String>, String, String, String);

/// Threat Response BC — SOAR aggregate repository.
///
/// Covers playbook CRUD, condition CRUD, block-rule lifecycle, pending-unblock
/// recovery queue, and the execution log. The settings (`soar_*`) and ACL
/// writes that block actions depend on live in `SettingRepo` and `AclRepo`
/// respectively; cross-aggregate atomicity is handled via
/// `DbAdminRepo::with_transaction` + `TxRepos`.
pub trait SoarRepo: Send + Sync {
    // --- Playbooks ---
    fn load_playbooks_with_actions(&self) -> Result<Vec<PlaybookRow>, Error>;
    fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error>;
    fn delete_playbook(&self, id: i64) -> Result<bool, Error>;
    fn seed_default_playbooks(&self) -> Result<(), Error>;

    // --- Playbook Conditions ---
    /// Returns: (condition_id, playbook_id, condition_type, operator, value, value2)
    #[allow(clippy::type_complexity)]
    fn load_all_playbook_conditions(&self) -> Result<Vec<(i64, i64, String, String, String, Option<String>)>, Error>;

    // --- Block Rules ---
    fn count_active_soar_blocks(&self) -> Result<u32, Error>;
    fn get_active_soar_blocks(&self) -> Result<Vec<(i64, String, i64, String)>, Error>;
    fn get_soar_block_by_id(&self, id: i64) -> Result<Option<(i64, String, i64, String)>, Error>;
    fn get_expired_soar_blocks(&self) -> Result<Vec<(i64, String, i64)>, Error>;
    fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error>;

    // --- Pending Unblock Recovery ---
    fn insert_pending_unblock(&self, source_ip: &str) -> Result<i64, Error>;
    fn load_pending_unblocks(&self) -> Result<Vec<(i64, String, i64)>, Error>;
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
    fn list_soar_executions(&self, limit: i64) -> Result<Vec<SoarExecutionRow>, Error>;

    // --- Intra-aggregate atomic operations ---

    /// Atomically create a playbook with its conditions and actions.
    /// All rows (playbook + conditions + actions) commit together; any error
    /// rolls back the whole insert. Returns the new playbook id.
    ///
    /// `actions` tuples: `(action_order, action_type, params_json)`.
    /// `conditions` tuples: `(condition_type, operator, value, value2)`.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<i64, Error>;

    /// Atomically update a playbook's metadata and replace its conditions
    /// and actions. Returns `Ok(false)` if no playbook with that id exists;
    /// otherwise `Ok(true)` after the whole update commits.
    fn update_playbook_atomic(
        &self,
        id: i64,
        row: &UpdatePlaybookRow,
        actions: &[(i64, String, String)],
        conditions: &[(String, String, String, Option<String>)],
    ) -> Result<bool, Error>;
}
