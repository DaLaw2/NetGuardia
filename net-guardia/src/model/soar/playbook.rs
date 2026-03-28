/// In-memory playbook representation.
#[derive(Debug, Clone)]
pub struct Playbook {
    pub id: i64,
    pub name: String,
    pub enabled: bool,
    pub trigger_event: String,
    pub condition_threshold: Option<f64>,
    pub cooldown_secs: i64,
    pub actions: Vec<PlaybookAction>,
}

#[derive(Debug, Clone)]
pub struct PlaybookAction {
    #[allow(dead_code)] // Kept for domain completeness; ordering handled by SQL ORDER BY
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}
