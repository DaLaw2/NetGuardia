use serde::Serialize;

use crate::domain::response::condition::ConditionType;
use crate::domain::response::error::SoarError;

#[derive(Clone)]
pub struct UpdatePlaybookInput {
    pub name: String,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
}

#[derive(Clone)]
pub struct ActionInput {
    pub action_order: i64,
    pub action_type: String,
    pub params_json: String,
}

#[derive(Clone)]
pub struct CreateConditionInput {
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

impl CreateConditionInput {
    pub fn new(
        condition_type: String,
        operator: Option<String>,
        value: String,
        value2: Option<String>,
    ) -> Result<Self, SoarError> {
        let operator = match operator {
            Some(operator) => operator,
            None => condition_type.parse::<ConditionType>()?.default_operator().to_string(),
        };
        Ok(Self {
            condition_type,
            operator,
            value,
            value2,
        })
    }
}

#[derive(Clone)]
pub struct CreatePlaybookInput {
    pub name: String,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub condition_count: Option<i64>,
    pub condition_window_secs: Option<i64>,
    pub cooldown_secs: i64,
    pub actions: Vec<ActionInput>,
    pub conditions: Vec<CreateConditionInput>,
}

#[derive(Serialize)]
pub struct ConditionView {
    pub id: i64,
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
}

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

#[derive(Serialize)]
pub struct ExecutionView {
    pub id: i64,
    pub playbook_id: i64,
    pub source_ip: Option<String>,
    pub trigger_event: String,
    pub actions_executed: serde_json::Value,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ActiveBlockView {
    pub id: i64,
    pub source_ip: String,
    pub playbook_id: i64,
    pub expires_at: String,
}

#[derive(Serialize)]
pub struct PendingUnblock {
    pub id: i64,
    pub source_ip: String,
    pub retry_count: i64,
    pub exhausted_at: Option<String>,
    pub last_error: Option<String>,
}
