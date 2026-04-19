//! Wire-level types for broadcasting ML source state to the frontend.
//!
//! Two layers:
//! - `ModelInfo` — stable facts about a loaded model (name, adapter kind, feature count).
//! - `ModelSourceStatus` — current state of the ML source: Dormant / Active / Error.
//!
//! The internal `core::ml::state::ModelSourceState` holds the actual model
//! adapter plus this metadata; it converts into `ModelSourceStatus` for
//! WebSocket / HTTP responses via `From`.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Public facts about a currently-loaded model. Drives the UI's ML Status panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Human-readable manifest name (e.g., "netguardia-v10").
    pub name: String,
    /// One of "autoencoder_only" | "classifier_only" | "multi_task".
    pub adapter_kind: String,
    /// When this model became Active (unix epoch seconds).
    pub loaded_at_secs: u64,
    /// Number of features the manifest declares. Useful for UI "31 features" display.
    pub features_count: usize,
    /// Recent inference QPS (rolling window). Zero before first tick.
    pub qps_recent: f32,
}

impl ModelInfo {
    pub fn new(name: String, adapter_kind: String, features_count: usize) -> Self {
        let loaded_at_secs = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            name,
            adapter_kind,
            loaded_at_secs,
            features_count,
            qps_recent: 0.0,
        }
    }
}

/// Wire-format ML source status. Broadcast to frontend; returned by
/// `GET /api/ml/models/current`. Serde-tagged so the frontend can discriminate
/// on the `state` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModelSourceStatus {
    /// No model loaded. Day 1 default; fusion runs with 3 sources.
    Dormant,
    /// Model loaded and serving inference. `info` populates the UI card.
    Active { info: ModelInfo },
    /// Last load attempt failed. UI shows the reason in red.
    /// `since_secs` is unix epoch seconds; `last_attempted_path` is the
    /// file that failed (if any).
    Error {
        msg: String,
        since_secs: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_attempted_path: Option<String>,
    },
}

impl ModelSourceStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub fn is_dormant(&self) -> bool {
        matches!(self, Self::Dormant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_dormant() {
        let json = serde_json::to_string(&ModelSourceStatus::Dormant).unwrap();
        assert!(json.contains("\"state\":\"dormant\""));
        let back: ModelSourceStatus = serde_json::from_str(&json).unwrap();
        assert!(back.is_dormant());
    }

    #[test]
    fn serde_roundtrip_active() {
        let status = ModelSourceStatus::Active {
            info: ModelInfo::new("netguardia-v10".into(), "multi_task".into(), 31),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"active\""));
        assert!(json.contains("\"adapter_kind\":\"multi_task\""));
        let back: ModelSourceStatus = serde_json::from_str(&json).unwrap();
        assert!(back.is_active());
    }

    #[test]
    fn serde_roundtrip_error() {
        let status = ModelSourceStatus::Error {
            msg: "feature mismatch".into(),
            since_secs: 1_700_000_000,
            last_attempted_path: Some("models/.staging/bad.onnx".into()),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"error\""));
        let back: ModelSourceStatus = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, ModelSourceStatus::Error { .. }));
    }
}
