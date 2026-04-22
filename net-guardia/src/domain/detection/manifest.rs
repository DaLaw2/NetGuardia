use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::detection::error::MLError;
use crate::domain::detection::feature_extractor::feature_is_known;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    ClassifierOnly,
    AutoencoderOnly,
    MultiTask,
}

impl AdapterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AdapterKind::ClassifierOnly => "classifier_only",
            AdapterKind::AutoencoderOnly => "autoencoder_only",
            AdapterKind::MultiTask => "multi_task",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ModelPaths {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoencoder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LabelSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playbook: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Thresholds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anomaly: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c2: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_min_confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ae: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_multiplier: Option<f32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Preprocessing {
    pub scaler_sidecar: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelManifest {
    pub name: String,
    pub adapter: AdapterKind,
    #[serde(default)]
    pub models: ModelPaths,
    pub features: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, LabelSpec>,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preprocessing: Option<Preprocessing>,
}

impl ModelManifest {
    pub fn validate(&self, path: &Path) -> Result<(), MLError> {
        if self.name.trim().is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "name is empty".to_string(),
            ));
        }
        if self.features.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "features is empty".to_string(),
            ));
        }
        for f in &self.features {
            if !feature_is_known(f) {
                return Err(MLError::UnknownFeature(f.clone()));
            }
        }
        match self.adapter {
            AdapterKind::MultiTask => {
                if self.models.autoencoder.is_none() || self.models.classifier.is_none() {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        "multi_task adapter requires both models.autoencoder and models.classifier".to_string(),
                    ));
                }
            }
            AdapterKind::ClassifierOnly | AdapterKind::AutoencoderOnly => {
                if self.models.model.is_none() {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        format!("{} adapter requires models.model", self.adapter.as_str()),
                    ));
                }
            }
        }
        self.validate_labels(path)?;
        self.validate_thresholds(path)?;
        Ok(())
    }

    fn validate_labels(&self, path: &Path) -> Result<(), MLError> {
        let mut seen: Vec<String> = Vec::with_capacity(self.labels.len());
        for spec in self.labels.values() {
            if let Some(n) = spec.confirmations
                && n == 0
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("label '{}' has confirmations: 0 (must be ≥ 1)", spec.name),
                ));
            }
            let lower = spec.name.to_ascii_lowercase();
            if seen.iter().any(|s| s == &lower) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate label name '{}' (case-insensitive)", spec.name),
                ));
            }
            seen.push(lower);
        }
        Ok(())
    }

    fn validate_thresholds(&self, path: &Path) -> Result<(), MLError> {
        if let Some(m) = self.thresholds.alert_multiplier
            && !(m.is_finite() && m > 0.0)
        {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!("thresholds.alert_multiplier must be finite and > 0 (got {m})"),
            ));
        }
        Ok(())
    }

    pub fn resolve_relative(manifest_path: &Path, relative: &str) -> PathBuf {
        manifest_path.parent().unwrap_or_else(|| Path::new(".")).join(relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V10_MANIFEST: &str = r#"
name: netguardia-v10
adapter: multi_task
models:
  autoencoder: deep_autoencoder.onnx
  classifier: classifier.onnx
features:
  - flow_duration
  - fwd_packets
  - bwd_packets
labels:
  "0": { name: Bot }
  "7": { name: Normal }
thresholds:
  anomaly: 0.9
  c2: 0.85
preprocessing:
  scaler_sidecar: inference_config.json
"#;

    #[test]
    fn parses_minimal_multitask() {
        let m: ModelManifest = serde_yaml_ng::from_str(V10_MANIFEST).expect("parse");
        assert_eq!(m.name, "netguardia-v10");
        assert_eq!(m.adapter, AdapterKind::MultiTask);
        assert_eq!(m.features.len(), 3);
        assert_eq!(m.models.autoencoder.as_deref(), Some("deep_autoencoder.onnx"));
        assert_eq!(m.models.classifier.as_deref(), Some("classifier.onnx"));
        assert_eq!(m.labels.len(), 2);
        assert_eq!(m.labels.get("0").map(|l| l.name.as_str()), Some("Bot"));
    }

    #[test]
    fn rejects_unknown_feature() {
        let yaml = r#"
name: bad
adapter: classifier_only
models:
  model: m.onnx
features:
  - this_feature_does_not_exist
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should reject unknown feature");
        assert!(matches!(err, MLError::UnknownFeature { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_multitask_missing_ae() {
        let yaml = r#"
name: bad
adapter: multi_task
models:
  classifier: c.onnx
features:
  - flow_duration
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should require autoencoder");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_empty_features() {
        let yaml = r#"
name: bad
adapter: classifier_only
models:
  model: m.onnx
features: []
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should reject empty features");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_zero_confirmations() {
        let yaml = r#"
name: bad
adapter: classifier_only
models:
  model: m.onnx
features:
  - flow_duration
labels:
  "0": { name: Bot, confirmations: 0 }
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should reject confirmations: 0");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_duplicate_label_name_ignoring_case() {
        let yaml = r#"
name: bad
adapter: classifier_only
models:
  model: m.onnx
features:
  - flow_duration
labels:
  "0": { name: Bot }
  "1": { name: BOT }
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should reject duplicate label names");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_non_positive_alert_multiplier() {
        let yaml = r#"
name: bad
adapter: classifier_only
models:
  model: m.onnx
features:
  - flow_duration
thresholds:
  alert_multiplier: 0
"#;
        let path = Path::new("/tmp/test-manifest.yaml");
        let parsed: ModelManifest = serde_yaml_ng::from_str(yaml).unwrap();
        let err = parsed.validate(path).expect_err("should reject alert_multiplier <= 0");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }
}
