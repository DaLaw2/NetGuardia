use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DryRunMatch {
    pub playbook_id: i64,
    pub playbook_name: String,
    pub enabled: bool,
    pub trigger_event: String,
    pub trigger_matches: bool,
    pub has_frequency_condition: bool,
    pub would_fire: bool,
    pub conditions: Vec<DryRunConditionResult>,
    pub actions: Vec<DryRunAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunConditionResult {
    pub condition_type: String,
    pub operator: String,
    pub value: String,
    pub value2: Option<String>,
    pub met: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunAction {
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}
