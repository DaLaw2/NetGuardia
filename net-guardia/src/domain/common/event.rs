use std::fmt;
use std::str::FromStr;

use serde::Serialize;

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

#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub source: DetectionSource,
    pub attack_type: String,
    pub confidence: f32,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: u8,
    pub packet_count: u64,
    pub flow_duration_us: u64,
    pub ae_score: f32,
    pub anomaly_score: f32,
    pub c2_score: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionDiagnostic {
    pub source: DetectionSource,
    pub name: String,
    pub value: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatDetectedEvent {
    pub attack_type: String,
    pub confidence: f32,
    pub source_ip: String,
    pub dest_ip: String,
    pub flow_count: u32,
    pub packet_rate: f64,
    pub protocol: u8,
    pub geoip_country: Option<String>,
    pub is_repeat_offender: bool,
    pub sources: Vec<DetectionSource>,
    pub active_source_count: usize,
    pub fused_confidence: f32,
    pub diagnostics: Vec<DetectionDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct DriftDetectedEvent {
    pub drifted_features: Vec<String>,
    pub max_deviation: f64,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub actor: String,
    pub action: String,
    pub detail: String,
}
