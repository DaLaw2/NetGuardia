/// Input for updating a playbook row (without actions/conditions).
pub struct UpdatePlaybookRow {
    pub name: String,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
}

/// Input for creating a single playbook condition.
pub struct CreateConditionInput {
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

/// Input for creating a new playbook.
pub struct CreatePlaybookInput {
    pub name: String,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
    pub actions: Vec<(String, String)>, // (action_type, params_json)
    pub conditions: Vec<CreateConditionInput>,
}

/// Persisted condition row for API responses.
pub struct ConditionData {
    pub id: i64,
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

/// Flattened playbook representation for API responses.
pub struct PlaybookData {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
    pub actions: Vec<ActionData>,
    pub conditions: Vec<ConditionData>,
}

pub struct ActionData {
    pub id: i64,
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}

/// Execution record from soar_executions table.
pub struct ExecutionData {
    pub id: i64,
    pub playbook_id: i64,
    pub source_ip: Option<String>,
    pub trigger_event: String,
    pub actions_executed: serde_json::Value,
    pub created_at: String,
}

/// Active block record from soar_block_rules table.
pub struct ActiveBlockData {
    pub id: i64,
    pub source_ip: String,
    pub playbook_id: i64,
    pub expires_at: String,
}
