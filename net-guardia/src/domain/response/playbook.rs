use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::response::condition::PlaybookCondition;

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

impl Playbook {
    pub fn matches_trigger(&self, event: &ThreatDetectedEvent) -> bool {
        self.enabled && self.trigger_event == event.attack_type
    }
}

#[derive(Debug, Clone)]
pub struct PlaybookAction {
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}
