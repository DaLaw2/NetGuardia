use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelIdentity {
    pub name: String,
    pub adapter_kind: String,
    pub features_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    #[serde(flatten)]
    pub identity: ModelIdentity,
    pub loaded_at_secs: u64,
    pub qps_recent: f32,
}

impl ModelInfo {
    pub fn new(name: String, adapter_kind: String, loaded_at_secs: u64, features_count: usize) -> Self {
        Self {
            identity: ModelIdentity {
                name,
                adapter_kind,
                features_count,
            },
            loaded_at_secs,
            qps_recent: 0.0,
        }
    }

    pub fn name(&self) -> &str {
        &self.identity.name
    }

    pub fn adapter_kind(&self) -> &str {
        &self.identity.adapter_kind
    }

    pub fn features_count(&self) -> usize {
        self.identity.features_count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModelSourceStatus {
    Dormant,
    Active {
        info: ModelInfo,
    },
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
            info: ModelInfo::new("netguardia-v10".into(), "pipeline".into(), 1_700_000_000, 31),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"active\""));
        assert!(json.contains("\"adapter_kind\":\"pipeline\""));
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
