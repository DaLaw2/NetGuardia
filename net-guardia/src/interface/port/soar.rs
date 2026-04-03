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

/// Port for SOAR-related persistence: playbooks, block rules, execution log, admin whitelist,
/// plus the settings and ACL methods that SOAR actions depend on.
pub trait SoarPort: Send + Sync {
    // --- Settings (used by rate-limit adjust/restore and email actions) ---
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error>;

    // --- ACL Rules (used by block_ip action and TTL scheduler cleanup) ---
    fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;
    fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;

    // --- Playbooks ---
    fn insert_playbook(
        &self,
        name: &str,
        trigger_event: &str,
        threshold: Option<f64>,
        count: Option<i64>,
        window: Option<i64>,
        cooldown: i64,
    ) -> Result<i64, Error>;
    fn insert_playbook_action(
        &self,
        playbook_id: i64,
        action_order: i64,
        action_type: &str,
        params_json: &str,
    ) -> Result<i64, Error>;
    fn load_playbooks_with_actions(&self) -> Result<Vec<PlaybookRow>, Error>;
    fn update_playbook(&self, id: i64, row: &UpdatePlaybookRow) -> Result<bool, Error>;
    fn update_playbook_enabled(&self, id: i64, enabled: bool) -> Result<bool, Error>;
    fn delete_playbook(&self, id: i64) -> Result<bool, Error>;
    fn delete_playbook_actions(&self, playbook_id: i64) -> Result<(), Error>;
    fn delete_playbook_conditions(&self, playbook_id: i64) -> Result<(), Error>;
    fn seed_default_playbooks(&self) -> Result<(), Error>;

    // --- Playbook Conditions ---
    fn insert_playbook_condition(
        &self,
        playbook_id: i64,
        condition_type: &str,
        operator: &str,
        value: &str,
        value2: Option<&str>,
    ) -> Result<i64, Error>;
    /// Returns: (condition_id, playbook_id, condition_type, operator, value, value2)
    #[allow(clippy::type_complexity)]
    fn load_all_playbook_conditions(&self) -> Result<Vec<(i64, i64, String, String, String, Option<String>)>, Error>;

    // --- Block Rules ---
    fn insert_soar_block_rule(&self, source_ip: &str, playbook_id: i64, expires_at: &str) -> Result<i64, Error>;
    fn count_active_soar_blocks(&self) -> Result<u32, Error>;
    fn get_active_soar_blocks(&self) -> Result<Vec<(i64, String, i64, String)>, Error>;
    fn get_soar_block_by_id(&self, id: i64) -> Result<Option<(i64, String, i64, String)>, Error>;
    fn get_expired_soar_blocks(&self) -> Result<Vec<(i64, String, i64)>, Error>;
    fn mark_soar_block_unblocked(&self, id: i64) -> Result<(), Error>;
    fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error>;

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

    // --- Admin Whitelist ---
    fn load_admin_whitelist(&self) -> Result<Vec<String>, Error>;
    fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error>;
    fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error>;
}
