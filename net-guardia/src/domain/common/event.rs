use std::fmt;
use std::str::FromStr;

use serde::Serialize;

// -- Detection Source ---------------------------------------------------------

/// Identifies which detection subsystem produced a detection.
/// Used for attribution tracking and cross-source deduplication.
///
/// Serialized as the canonical `Display` form ("ML", "Suricata", "Beaconing",
/// "Correlation") so the WebSocket wire matches the SOAR `SingleSourceHigh`
/// `value` field — frontend rendering and playbook authoring share one
/// vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum DetectionSource {
    ML,
    Correlation,
    Beaconing,
    Suricata,
}

impl fmt::Display for DetectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectionSource::ML => write!(f, "ML"),
            DetectionSource::Correlation => write!(f, "Correlation"),
            DetectionSource::Beaconing => write!(f, "Beaconing"),
            DetectionSource::Suricata => write!(f, "Suricata"),
        }
    }
}

impl FromStr for DetectionSource {
    type Err = ();

    /// Accepts the canonical `Display` form plus common aliases so playbook
    /// authors can write `"CV"` for Beaconing or `"Graph"` for Correlation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ML" | "ml" => Ok(Self::ML),
            "Suricata" | "suricata" => Ok(Self::Suricata),
            "Beaconing" | "beaconing" | "CV" | "cv" => Ok(Self::Beaconing),
            "Correlation" | "correlation" | "Graph" | "graph" => Ok(Self::Correlation),
            _ => Err(()),
        }
    }
}

// -- Detection Event (internal pipeline) --------------------------------------

/// Raw detection from any source. Sent via mpsc channel to DetectionOrchestrator.
/// Not published through broadcast — this is a private internal pipeline.
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
    /// Per-model scores for observability (ML source only)
    pub ae_score: f32,
    pub anomaly_score: f32,
    pub c2_score: f32,
}

// -- Threat Events ------------------------------------------------------------

/// Fired when the DetectionOrchestrator emits a deduplicated, enriched threat.
/// Consumed by the SOAR engine to trigger automated responses, and broadcast
/// to the dashboard over `/ws/fusion` so the operator's "Recent Threats"
/// stream surfaces post-fusion (multi-source) detections rather than raw
/// per-flow ML alerts.
#[derive(Debug, Clone, Serialize)]
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
    /// Which detection sources contributed to this threat (for attribution).
    /// Single-source events have length 1; fused events have 2..=4.
    pub sources: Vec<DetectionSource>,
    /// Number of distinct sources that contributed to this event.
    /// Used by SOAR `MultiSourceMin` / `SingleSourceHigh` conditions —
    /// counts unique sources, not per-source fires within the window.
    pub active_source_count: usize,
    /// Cross-source fused confidence (1 − ∏(1 − c_i)). Equal to
    /// `confidence` after the fusion engine runs; retained as a separate
    /// field so SOAR policies can discriminate "single source" from
    /// "fused multi-source" numerically identical confidences.
    pub fused_confidence: f32,
    /// Per-model scores for debugging false positives.
    pub ae_score: f32,
    pub anomaly_score: f32,
    pub c2_score: f32,
}

/// Fired when the ML drift detector finds feature drift beyond 3 sigma.
#[derive(Debug, Clone)]
pub struct DriftDetectedEvent {
    pub drifted_features: Vec<String>,
    pub max_deviation: f64,
}

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
