use crate::interface::communication::event::Event;
use crate::model::direction::Direction;

// ── ML Events ────────────────────────────────────────────────────────

/// Fired when the ML engine detects a potential threat.
#[derive(Debug, Clone)]
pub struct ThreatDetectedEvent {
    pub flow_key: String,
    pub direction: Direction,
    pub attack_type: String,
    pub confidence: f32,
    pub ae_score: f32,
}

impl Event for ThreatDetectedEvent {}

/// Fired after each ML inference tick with summary stats.
#[derive(Debug, Clone)]
pub struct InferenceCompletedEvent {
    pub total_flows: usize,
    pub malicious_flows: usize,
    pub benign_flows: usize,
    pub elapsed_ms: u32,
}

impl Event for InferenceCompletedEvent {}

// ── System Events ────────────────────────────────────────────────────

/// Fired when enforce mode changes (monitor ↔ enforce).
#[derive(Debug, Clone)]
pub struct EnforceModeChangedEvent {
    pub old_mode: String,
    pub new_mode: String,
}

impl Event for EnforceModeChangedEvent {}

/// Fired when XDP attachment completes (or falls back).
#[derive(Debug, Clone)]
pub struct XdpAttachedEvent {
    pub interface: String,
    pub mode: String, // "drv" or "skb"
}

impl Event for XdpAttachedEvent {}

// ── ACL Events ───────────────────────────────────────────────────────

/// Fired when an ACL rule is added or removed.
#[derive(Debug, Clone)]
pub struct AclRuleChangedEvent {
    pub action: String, // "added" or "removed"
    pub ip_version: u8,
    pub direction: String,
    pub list_type: String,
    pub ip_address: String,
    pub port: u16,
}

impl Event for AclRuleChangedEvent {}

// ── Auth Events ──────────────────────────────────────────────────────

/// Fired when a login attempt fails (for auditing).
#[derive(Debug, Clone)]
pub struct LoginFailedEvent {
    pub username: String,
    pub failure_count: u32,
    pub locked: bool,
}

impl Event for LoginFailedEvent {}

/// Fired when a user changes their password.
#[derive(Debug, Clone)]
pub struct PasswordChangedEvent {
    pub user_id: i64,
    pub username: String,
}

impl Event for PasswordChangedEvent {}
