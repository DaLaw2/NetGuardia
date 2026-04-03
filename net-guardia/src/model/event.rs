use std::fmt;

use crate::interface::communication::event::Event;

// -- Detection Source ---------------------------------------------------------

/// Identifies which detection subsystem produced a detection.
/// Used for attribution tracking and future cross-source deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectionSource {
    ML,
    Correlation,
    Beaconing,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionSource::ML => write!(f, "ML"),
            DetectionSource::Correlation => write!(f, "Correlation"),
            DetectionSource::Beaconing => write!(f, "Beaconing"),
        }
    }
}

// -- Detection Event (internal pipeline) --------------------------------------

/// Raw detection from any source. Sent via mpsc channel to DetectionOrchestrator.
/// Not published through CommunicationManager — this is a private internal pipeline.
#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub source: DetectionSource,
    /// Normalized attack type (e.g. "brute_force", "port_scan", "threat_detected")
    pub attack_type: String,
    pub confidence: f32,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: u8,
    pub packet_count: u64,
    pub flow_duration_us: u64,
}

// -- Threat Events ------------------------------------------------------------

/// Fired when the DetectionOrchestrator emits a deduplicated, enriched threat.
/// Consumed by the SOAR engine to trigger automated responses.
#[derive(Debug, Clone)]
pub struct ThreatDetectedEvent {
    pub attack_type: String,
    pub confidence: f32,
    /// Source IP address (e.g. "192.168.1.100")
    pub source_ip: String,
    /// Destination IP address (e.g. "10.0.0.1")
    pub dest_ip: String,
    /// Number of alert flows from this src_ip in recent window
    pub flow_count: u32,
    /// Packets per second of the triggering flow
    pub packet_rate: f64,
    /// IP protocol number (6=TCP, 17=UDP)
    pub protocol: u8,
    /// Source country ISO 3166-1 alpha-2 code, None if GeoIP unavailable
    pub geoip_country: Option<String>,
    /// Whether this src_ip had a block action in the past 24h
    pub is_repeat_offender: bool,
    /// Which detection sources contributed to this threat (for attribution)
    pub sources: Vec<DetectionSource>,
}

impl Event for ThreatDetectedEvent {}

/// Fired when the ML drift detector finds feature drift beyond 3 sigma.
#[derive(Debug, Clone)]
pub struct DriftDetectedEvent {
    pub drifted_features: Vec<String>,
    pub max_deviation: f64,
}

impl Event for DriftDetectedEvent {}

// -- Audit Events -------------------------------------------------------------

/// Fired for auditable actions (enforce mode changes, playbook CRUD, etc.).
/// Consumed by AuditLogger to persist to DB and structured logs.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Who performed the action: "admin", "system", "soar"
    pub actor: String,
    /// What action was performed: "enforce_mode_changed", "playbook_created", etc.
    pub action: String,
    /// JSON string with action-specific details
    pub detail: String,
}

impl Event for AuditEvent {}
