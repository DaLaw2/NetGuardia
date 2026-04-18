//! DTOs for the SOAR dry-run endpoint. Returned to the HTTP layer
//! verbatim, so any rename here is a wire-format change.

use serde::Serialize;

/// One playbook's simulated outcome against a synthetic event. Reports
/// what would fire, what conditions passed, and what actions would
/// execute — without actually invoking any of them.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunMatch {
    pub playbook_id: i64,
    pub playbook_name: String,
    pub enabled: bool,
    pub trigger_event: String,
    /// The playbook's `trigger_event` matched the event's `attack_type`.
    pub trigger_matches: bool,
    /// The playbook has at least one `frequency` condition whose outcome
    /// depends on runtime history — dry-run cannot accurately evaluate
    /// it, so the UI should warn the admin that real firing may differ.
    pub has_frequency_condition: bool,
    /// `trigger_matches` and every non-frequency condition reported met.
    /// `has_frequency_condition=true` does NOT force this false — the
    /// frequency branch is treated as "passes in dry-run" and flagged
    /// for the admin to interpret.
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
    /// Human-readable explanation for the frontend to surface, populated
    /// when the answer is non-obvious (e.g. "skipped — requires history"
    /// for Frequency, or "sources=[ML] confidence=0.90 target=Suricata"
    /// for a mismatching SingleSourceHigh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunAction {
    pub action_order: i64,
    pub action_type: String,
    pub params: serde_json::Value,
}
