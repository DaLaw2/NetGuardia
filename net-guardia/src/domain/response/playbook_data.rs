use serde::Serialize;

/// Input for updating a playbook row (without actions/conditions).
#[derive(Clone)]
pub struct UpdatePlaybookInput {
    pub name: String,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
}

/// Input for a single playbook action in atomic create/update operations.
#[derive(Clone)]
pub struct ActionInput {
    pub action_order: i64,
    pub action_type: String,
    pub params_json: String,
}

/// Input for creating a single playbook condition.
#[derive(Clone)]
pub struct CreateConditionInput {
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

impl CreateConditionInput {
    pub fn new(condition_type: String, operator: Option<String>, value: String, value2: Option<String>) -> Self {
        let operator = operator.unwrap_or_else(|| default_operator_for(&condition_type).to_string());
        Self {
            condition_type,
            operator,
            value,
            value2,
        }
    }
}

fn default_operator_for(condition_type: &str) -> &'static str {
    match condition_type {
        "threshold" | "frequency" => ">=",
        "source_country" | "ip_pattern" => "in",
        "repeat_offender" => "==",
        _ => ">=",
    }
}

/// Input for creating a new playbook.
#[derive(Clone)]
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
#[derive(Serialize)]
pub struct ConditionView {
    pub id: i64,
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

/// Flattened playbook representation for API responses.
#[derive(Serialize)]
pub struct PlaybookView {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
    pub actions: Vec<ActionView>,
    pub conditions: Vec<ConditionView>,
}

#[derive(Serialize)]
pub struct ActionView {
    pub id: i64,
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}

/// Execution record from soar_executions table.
#[derive(Serialize)]
pub struct ExecutionView {
    pub id: i64,
    pub playbook_id: i64,
    pub source_ip: Option<String>,
    pub trigger_event: String,
    pub actions_executed: serde_json::Value,
    pub created_at: String,
}

/// Active block record from soar_block_rules table.
#[derive(Serialize)]
pub struct ActiveBlockView {
    pub id: i64,
    pub source_ip: String,
    pub playbook_id: i64,
    pub expires_at: String,
}

/// Pending unblock recovery record.
#[derive(Serialize)]
pub struct PendingUnblock {
    pub id: i64,
    pub source_ip: String,
    pub retry_count: i64,
}
