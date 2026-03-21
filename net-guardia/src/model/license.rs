use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub ingress_mac: String,
    pub egress_mac: String,
    pub expires: String,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub payload: Option<LicensePayload>,
    pub valid: bool,
    pub days_remaining: i64,
}

impl LicenseInfo {
    pub fn unlicensed() -> Self {
        Self {
            payload: None,
            valid: false,
            days_remaining: 0,
        }
    }
}
