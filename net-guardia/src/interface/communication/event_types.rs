use crate::interface::communication::event::Event;

// ── ML Events ────────────────────────────────────────────────────────

/// Fired when the ML engine detects a potential threat.
/// Consumed by the SOAR engine to trigger automated responses.
#[derive(Debug, Clone)]
pub struct ThreatDetectedEvent {
    pub attack_type: String,
    pub confidence: f32,
    /// Source IP address (e.g. "192.168.1.100")
    pub source_ip: String,
    /// Destination IP address (e.g. "10.0.0.1")
    pub dest_ip: String,
}

impl Event for ThreatDetectedEvent {}
