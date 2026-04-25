use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::{AdapterKind, LabelSpec, ModelManifest};
use crate::domain::detection::ml_inference_config::MLInferenceConfig;

impl MLInferenceConfig {
    pub fn load_file(file: &str) -> Result<Self, MLError> {
        let path = PathBuf::from("models").join(file);
        Self::load_file_at(&path)
    }

    fn load_file_at(path: &Path) -> Result<Self, MLError> {
        let content = fs::read_to_string(path)
            .map_err(|e| MLError::ConfigLoadFailed(path.to_path_buf(), format!("read failed: {e}")))?;
        let config: MLInferenceConfig =
            serde_json::from_str(&content).map_err(|e| MLError::ConfigParseFailed(e.to_string()))?;
        validate(&config)?;
        Ok(config)
    }

    /// Load a `MLInferenceConfig` by combining a manifest with its scaler sidecar.
    /// The manifest supplies the authoritative feature list and per-label metadata;
    /// the sidecar JSON supplies the numeric preprocessing arrays (scaler / clip / weights).
    ///
    /// Consistency is enforced: manifest `features` must match the sidecar's
    /// `ae_feature_names` exactly (order-sensitive). Any drift between the two is a
    /// deployment bug, not a silent override.
    pub fn from_manifest_with_sidecar(manifest_path: &Path) -> Result<(Self, ModelManifest), MLError> {
        let manifest = ModelManifest::load(manifest_path)?;
        let sidecar_rel = manifest
            .preprocessing
            .as_ref()
            .map(|p| p.scaler_sidecar.as_str())
            .ok_or_else(|| {
                MLError::ManifestInvalid(
                    manifest_path.to_path_buf(),
                    "preprocessing.scaler_sidecar is required for v1 (scaler arrays live there)".to_string(),
                )
            })?;
        let sidecar_path = ModelManifest::resolve_relative(manifest_path, sidecar_rel);
        let mut config = Self::load_file_at(&sidecar_path)?;

        reconcile_features(&manifest, &config, manifest_path)?;
        apply_manifest_overrides(&manifest, &mut config);
        validate_for_adapter(&config, manifest.adapter)?;

        Ok((config, manifest))
    }
}

/// Shape checks that apply to every sidecar regardless of adapter kind:
/// feature list non-empty, scaler arrays match feature count. Per-adapter
/// output-head counts live in `validate_for_adapter` and only run via the
/// manifest path where the adapter kind is known.
fn validate(config: &MLInferenceConfig) -> Result<(), MLError> {
    if config.ae_feature_names.is_empty() {
        return Err(MLError::ConfigParseFailed("ae_feature_names is empty"));
    }
    if config.ae_scaler_mean.len() != config.ae_feature_names.len() {
        return Err(MLError::ConfigParseFailed("scaler mean length mismatch"));
    }
    if config.ae_scaler_std.len() != config.ae_feature_names.len() {
        return Err(MLError::ConfigParseFailed("scaler std length mismatch"));
    }
    Ok(())
}

/// Adapter-specific output-head count check. MultiTask ships three heads
/// (anomaly / class_probs / c2_score); single-head adapters (Classifier,
/// Autoencoder) ship one. Mismatch here means the sidecar belongs to a
/// different adapter kind than the manifest declares — a deployment bug
/// rather than a runtime fault.
fn validate_for_adapter(config: &MLInferenceConfig, adapter: AdapterKind) -> Result<(), MLError> {
    let expected = match adapter {
        AdapterKind::MultiTask => 3,
        AdapterKind::ClassifierOnly | AdapterKind::AutoencoderOnly => 1,
    };
    if config.output_names.len() != expected {
        return Err(MLError::ConfigParseFailed(match adapter {
            AdapterKind::MultiTask => "MultiTaskModel requires exactly 3 output_names (anomaly, class_probs, c2_score)",
            AdapterKind::ClassifierOnly => "ClassifierOnly adapter requires exactly 1 output_name (class_probs)",
            AdapterKind::AutoencoderOnly => "AutoencoderOnly adapter requires exactly 1 output_name (reconstruction)",
        }));
    }
    Ok(())
}

fn reconcile_features(
    manifest: &ModelManifest,
    config: &MLInferenceConfig,
    manifest_path: &Path,
) -> Result<(), MLError> {
    if manifest.features.len() != config.ae_feature_names.len() {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            format!(
                "feature count mismatch with sidecar: manifest declares {}, sidecar lists {}",
                manifest.features.len(),
                config.ae_feature_names.len()
            ),
        ));
    }
    for (i, (mf, sf)) in manifest.features.iter().zip(config.ae_feature_names.iter()).enumerate() {
        if mf != sf {
            return Err(MLError::ManifestInvalid(
                manifest_path.to_path_buf(),
                format!("feature[{i}] mismatch: manifest='{mf}' vs sidecar='{sf}'"),
            ));
        }
    }
    Ok(())
}

fn apply_manifest_overrides(manifest: &ModelManifest, config: &mut MLInferenceConfig) {
    if !manifest.labels.is_empty() {
        config.attack_labels = manifest_labels_to_map(&manifest.labels);
    }
    if let Some(v) = manifest.thresholds.anomaly {
        config.anomaly_threshold = v;
    }
    if let Some(v) = manifest.thresholds.c2 {
        config.c2_threshold = v;
    }
    if let Some(v) = manifest.thresholds.class_min_confidence {
        config.class_min_confidence = v;
    }
    if let Some(v) = manifest.thresholds.ae {
        config.ae_threshold = v;
    }
    if let Some(v) = manifest.thresholds.alert_multiplier {
        config.alert_threshold_multiplier = v;
    }
}

fn manifest_labels_to_map(labels: &BTreeMap<String, LabelSpec>) -> HashMap<String, String> {
    labels.iter().map(|(k, v)| (k.clone(), v.name.clone())).collect()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::Write;

    use super::*;
    use crate::domain::detection::ml_detection::ClipParams;

    /// Integration test: the shipped `models/manifest.yaml` must successfully pair
    /// with its scaler sidecar to yield a valid `MLInferenceConfig`. Skipped silently
    /// when run outside the repo root (no `models/` directory).
    #[test]
    fn v10_manifest_and_sidecar_load_successfully() {
        let manifest_path = Path::new("models/manifest.yaml");
        if !manifest_path.exists() {
            eprintln!("skipping: models/manifest.yaml absent (not in repo root?)");
            return;
        }
        let (cfg, manifest) = MLInferenceConfig::from_manifest_with_sidecar(manifest_path)
            .expect("v10 manifest + sidecar should load cleanly");
        assert_eq!(manifest.name, "netguardia-v10");
        assert_eq!(cfg.ae_feature_names.len(), 31);
        assert_eq!(cfg.classifier_feature_names.len(), 32);
        // Label map came from manifest, not sidecar.
        assert_eq!(cfg.attack_labels.get("0").map(String::as_str), Some("Bot"));
        assert_eq!(cfg.attack_labels.get("7").map(String::as_str), Some("Normal"));
    }

    #[test]
    fn feature_mismatch_between_manifest_and_sidecar_is_rejected() {
        // Build a minimal sidecar JSON with 2 features.
        let sidecar = MLInferenceConfig {
            ae_feature_names: vec!["flow_duration".into(), "fwd_packets".into()],
            ae_clip_params: HashMap::from([
                ("flow_duration".into(), ClipParams { lower: 0.0, upper: 1.0 }),
                ("fwd_packets".into(), ClipParams { lower: 0.0, upper: 1.0 }),
            ]),
            ae_scaler_mean: vec![0.0, 0.0],
            ae_scaler_std: vec![1.0, 1.0],
            ae_post_clip_min: -5.0,
            ae_post_clip_max: 5.0,
            ae_threshold: 0.5,
            classifier_feature_names: vec!["flow_duration".into(), "fwd_packets".into(), "ae_anomaly_score".into()],
            attack_labels: HashMap::new(),
            anomaly_threshold: 0.5,
            c2_threshold: 0.5,
            class_min_confidence: 0.4,
            alert_threshold_multiplier: 1.2,
            model_type: "MultiTaskModel".into(),
            output_names: vec!["anomaly".into(), "class_probs".into(), "c2_score".into()],
            ae_feature_weights: HashMap::new(),
        };

        let tmp = env::temp_dir().join("netguardia-m1-mismatch-test");
        fs::create_dir_all(&tmp).unwrap();
        let sidecar_path = tmp.join("sidecar.json");
        let manifest_path = tmp.join("manifest.yaml");
        let mut f = fs::File::create(&sidecar_path).unwrap();
        f.write_all(serde_json::to_string(&sidecar).unwrap().as_bytes())
            .unwrap();

        // Manifest lists 3 features, sidecar has 2 — must fail.
        let manifest_yaml = r#"
name: test
adapter: multi_task
models:
  autoencoder: ae.onnx
  classifier: c.onnx
features:
  - flow_duration
  - fwd_packets
  - dst_port
preprocessing:
  scaler_sidecar: sidecar.json
"#;
        fs::write(&manifest_path, manifest_yaml).unwrap();
        let err =
            MLInferenceConfig::from_manifest_with_sidecar(&manifest_path).expect_err("should reject count mismatch");
        assert!(matches!(err, MLError::ManifestInvalid { .. }), "got {err:?}");
    }
}
