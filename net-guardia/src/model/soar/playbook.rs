use crate::model::soar::condition::PlaybookCondition;

/// In-memory playbook representation.
#[derive(Debug, Clone)]
pub struct Playbook {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub trigger_event: String,
    pub cooldown_secs: i64,
    pub actions: Vec<PlaybookAction>,
    pub conditions: Vec<PlaybookCondition>,
}

#[derive(Debug, Clone)]
pub struct PlaybookAction {
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}
