use std::fs;
use std::path::{Path, PathBuf};

use crate::adapter::model_loading::manifest::load_model_manifest;
use crate::domain::detection::error::MLError;
use crate::domain::detection::feature_extractor::feature_is_known;
use crate::domain::detection::manifest::{ModelManifest, PreprocessingStep, StageInputSource, StageKind, StageSpec};
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::interface::detection::model_config_loader::ModelConfigLoader;

#[derive(Default)]
pub struct FsModelConfigLoader;

impl FsModelConfigLoader {
    pub fn load_file(&self, file: &str) -> Result<MLInferenceConfig, MLError> {
        let path = PathBuf::from("models").join(file);
        Self::load_file_at(&path)
    }

    fn load_file_at(path: &Path) -> Result<MLInferenceConfig, MLError> {
        let content = fs::read_to_string(path).map_err(|e| MLError::ConfigLoadFailed(path.to_path_buf(), e))?;
        let config: MLInferenceConfig = serde_json::from_str(&content).map_err(MLError::ConfigParseFailed)?;
        validate_config(&config)?;
        Ok(config)
    }

    pub fn load_manifest_with_sidecar(
        &self,
        manifest_path: &Path,
    ) -> Result<(MLInferenceConfig, ModelManifest), MLError> {
        let manifest = load_model_manifest(manifest_path)?;
        let sidecar_rel = manifest.primary_scaler_sidecar().ok_or_else(|| {
            MLError::ManifestInvalid(
                manifest_path.to_path_buf(),
                "primary model requires a preprocessing.standard_scaler sidecar".to_string(),
            )
        })?;
        let sidecar_path = ModelManifest::resolve_relative(manifest_path, sidecar_rel);
        let config = Self::load_file_at(&sidecar_path)?;

        validate_manifest_alignment(&manifest, &config, manifest_path)?;
        validate_preprocessing_sidecar_params(&manifest, &config)?;

        Ok((config, manifest))
    }
}

impl ModelConfigLoader for FsModelConfigLoader {
    fn load_manifest(&self, manifest_path: &Path) -> Result<ModelManifest, MLError> {
        load_model_manifest(manifest_path)
    }

    fn load_manifest_with_sidecar(&self, manifest_path: &Path) -> Result<(MLInferenceConfig, ModelManifest), MLError> {
        FsModelConfigLoader::load_manifest_with_sidecar(self, manifest_path)
    }
}

fn validate_config(config: &MLInferenceConfig) -> Result<(), MLError> {
    if config.ae_feature_names.is_empty() {
        return Err(MLError::ConfigInvalid("ae_feature_names is empty"));
    }
    if config.ae_scaler_mean.len() != config.ae_feature_names.len() {
        return Err(MLError::ConfigInvalid("scaler mean length mismatch"));
    }
    if config.ae_scaler_std.len() != config.ae_feature_names.len() {
        return Err(MLError::ConfigInvalid("scaler std length mismatch"));
    }
    validate_f64_slice("ae_scaler_mean", &config.ae_scaler_mean)?;
    validate_non_negative_f64_slice("ae_scaler_std", &config.ae_scaler_std)?;
    validate_clip_range("ae_post_clip", config.ae_post_clip_min, config.ae_post_clip_max)?;
    for (name, params) in &config.ae_clip_params {
        validate_clip_range(&format!("ae_clip_params.{name}"), params.lower, params.upper)?;
    }
    for (name, params) in &config.minmax_params {
        validate_clip_range(&format!("minmax_params.{name}"), params.min, params.max)?;
    }
    for (name, params) in &config.robust_params {
        if !(params.center.is_finite() && params.scale.is_finite() && params.scale >= 0.0) {
            return Err(MLError::ConfigInvalid(format!(
                "robust_params.{name} must have finite center and scale >= 0"
            )));
        }
    }
    for (name, params) in &config.quantile_params {
        validate_quantile_params(name, &params.values, &params.quantiles)?;
    }
    for name in &config.ae_feature_names {
        if !feature_is_known(name) {
            return Err(MLError::ConfigInvalid(format!(
                "ae_feature_names contains unknown feature '{name}'"
            )));
        }
    }
    Ok(())
}

fn validate_manifest_alignment(
    manifest: &ModelManifest,
    config: &MLInferenceConfig,
    manifest_path: &Path,
) -> Result<(), MLError> {
    let Some(primary) = manifest.stages.first() else {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            "manifest does not declare a primary stage".to_string(),
        ));
    };

    let primary_features = feature_input_names(primary);
    if config.ae_feature_names != primary_features {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            "primary stage feature inputs must match ae_feature_names in the preprocessing sidecar".to_string(),
        ));
    }

    let Some(classifier) = manifest.stages.iter().find(|stage| stage.kind == StageKind::Classifier) else {
        return Ok(());
    };

    let classifier_inputs = stage_input_names(classifier);
    if config.classifier_feature_names != classifier_inputs {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            "classifier stage inputs must match classifier_feature_names in the preprocessing sidecar".to_string(),
        ));
    }
    Ok(())
}

fn validate_preprocessing_sidecar_params(manifest: &ModelManifest, config: &MLInferenceConfig) -> Result<(), MLError> {
    for stage in &manifest.stages {
        for step in &stage.preprocessing {
            for name in feature_input_names(stage) {
                match step {
                    PreprocessingStep::StandardScaler { .. } => {
                        if !config.ae_feature_names.iter().any(|feature| feature == &name) {
                            return Err(MLError::ConfigInvalid(format!(
                                "standard_scaler missing feature '{name}' in sidecar"
                            )));
                        }
                    }
                    PreprocessingStep::MinMaxScaler { .. } => {
                        if !config.minmax_params.contains_key(&name) {
                            return Err(MLError::ConfigInvalid(format!(
                                "minmax_scaler missing params for feature '{name}'"
                            )));
                        }
                    }
                    PreprocessingStep::RobustScaler { .. } => {
                        if !config.robust_params.contains_key(&name) {
                            return Err(MLError::ConfigInvalid(format!(
                                "robust_scaler missing params for feature '{name}'"
                            )));
                        }
                    }
                    PreprocessingStep::Quantile { .. } => {
                        if !config.quantile_params.contains_key(&name) {
                            return Err(MLError::ConfigInvalid(format!(
                                "quantile preprocessing missing params for feature '{name}'"
                            )));
                        }
                    }
                    PreprocessingStep::LogTransform { .. } | PreprocessingStep::Clip { .. } => {}
                }
            }
        }
    }
    Ok(())
}

fn feature_input_names(stage: &StageSpec) -> Vec<String> {
    stage
        .inputs
        .iter()
        .filter(|input| input.source == StageInputSource::Feature)
        .map(|input| input.name.clone())
        .collect()
}

fn stage_input_names(stage: &StageSpec) -> Vec<String> {
    stage.inputs.iter().map(|input| input.name.clone()).collect()
}

fn validate_f64_slice(field: &str, values: &[f64]) -> Result<(), MLError> {
    if let Some(value) = values.iter().find(|v| !v.is_finite()) {
        return Err(MLError::ConfigInvalid(format!(
            "{field} must contain only finite values (got {value})"
        )));
    }
    Ok(())
}

fn validate_non_negative_f64_slice(field: &str, values: &[f64]) -> Result<(), MLError> {
    if let Some(value) = values.iter().find(|v| !(v.is_finite() && **v >= 0.0)) {
        return Err(MLError::ConfigInvalid(format!(
            "{field} must contain only finite values >= 0 (got {value})"
        )));
    }
    Ok(())
}

fn validate_clip_range(field: &str, lower: f64, upper: f64) -> Result<(), MLError> {
    if !(lower.is_finite() && upper.is_finite() && lower <= upper) {
        return Err(MLError::ConfigInvalid(format!(
            "{field} must be finite and ordered lower <= upper (got {lower}..{upper})"
        )));
    }
    Ok(())
}

fn validate_quantile_params(field: &str, values: &[f64], quantiles: &[f64]) -> Result<(), MLError> {
    if values.len() != quantiles.len() || values.len() < 2 {
        return Err(MLError::ConfigInvalid(format!(
            "quantile_params.{field} requires equal-length values/quantiles with at least two points"
        )));
    }
    validate_f64_slice(&format!("quantile_params.{field}.values"), values)?;
    validate_f64_slice(&format!("quantile_params.{field}.quantiles"), quantiles)?;
    if values.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(MLError::ConfigInvalid(format!(
            "quantile_params.{field}.values must be sorted ascending"
        )));
    }
    if quantiles.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(MLError::ConfigInvalid(format!(
            "quantile_params.{field}.quantiles must be sorted ascending"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::env;
    use std::io::Write;

    use super::*;
    use crate::domain::detection::manifest::{
        AlertRuleSpec, ArtifactKind, ArtifactSpec, AttackMappingSpec, DetectionRuleSpec, LabelSpec, OutputHeadSpec,
        OutputRole, OutputSemantic, PipelineOutputSpec, PreprocessingStep, RuntimeSpec, StageInputSource,
        StageInputSpec, StageKind, StageSpec,
    };
    use crate::domain::detection::ml_detection::ClipParams;

    fn test_manifest() -> ModelManifest {
        ModelManifest {
            name: "test".into(),
            version: 1,
            runtime: RuntimeSpec {
                pipeline_mode: "dag".into(),
                normal_label: "Normal".into(),
            },
            artifacts: vec![
                ArtifactSpec {
                    id: "ae_onnx".into(),
                    file: "deep_autoencoder.onnx".into(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "classifier_onnx".into(),
                    file: "classifier.onnx".into(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "sidecar".into(),
                    file: "sidecar.json".into(),
                    kind: ArtifactKind::Sidecar,
                },
            ],
            stages: vec![
                StageSpec {
                    id: "anomaly_detector".into(),
                    kind: StageKind::Autoencoder,
                    model_file: "deep_autoencoder.onnx".into(),
                    depends_on: vec![],
                    inputs: vec![
                        StageInputSpec {
                            name: "flow_duration".into(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "fwd_packets".into(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                    ],
                    preprocessing: vec![
                        PreprocessingStep::StandardScaler {
                            sidecar: "sidecar.json".into(),
                        },
                        PreprocessingStep::Clip { min: -5.0, max: 5.0 },
                    ],
                    output_heads: vec![OutputHeadSpec {
                        name: "ae_anomaly_score".into(),
                        index: 0,
                        shape: vec!["1".into()],
                        semantic: OutputSemantic::AnomalyScore,
                        threshold: Some(0.23),
                        min_confidence: None,
                    }],
                },
                StageSpec {
                    id: "classifier".into(),
                    kind: StageKind::Classifier,
                    model_file: "classifier.onnx".into(),
                    depends_on: vec!["anomaly_detector".into()],
                    inputs: vec![
                        StageInputSpec {
                            name: "flow_duration".into(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "fwd_packets".into(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "ae_anomaly_score".into(),
                            source: StageInputSource::StageOutput,
                            stage: Some("anomaly_detector".into()),
                            output: Some("ae_anomaly_score".into()),
                        },
                    ],
                    preprocessing: vec![],
                    output_heads: vec![
                        OutputHeadSpec {
                            name: "anomaly".into(),
                            index: 0,
                            shape: vec!["1".into()],
                            semantic: OutputSemantic::Binary,
                            threshold: Some(0.91),
                            min_confidence: None,
                        },
                        OutputHeadSpec {
                            name: "class_probs".into(),
                            index: 1,
                            shape: vec!["10".into()],
                            semantic: OutputSemantic::Multiclass,
                            threshold: None,
                            min_confidence: Some(0.4),
                        },
                    ],
                },
            ],
            outputs: vec![
                PipelineOutputSpec {
                    stage: "anomaly_detector".into(),
                    output: "ae_anomaly_score".into(),
                    alias: Some("ae_anomaly_score".into()),
                    role: OutputRole::AnomalyScore,
                },
                PipelineOutputSpec {
                    stage: "classifier".into(),
                    output: "anomaly".into(),
                    alias: Some("anomaly".into()),
                    role: OutputRole::BinaryScore,
                },
                PipelineOutputSpec {
                    stage: "classifier".into(),
                    output: "class_probs".into(),
                    alias: Some("class_probs".into()),
                    role: OutputRole::ClassProbabilities,
                },
            ],
            detection_rules: vec![
                DetectionRuleSpec::Threshold {
                    id: "anomaly_threshold".into(),
                    output: "anomaly".into(),
                    attack: AttackMappingSpec::PredictedClass {
                        output: "class_probs".into(),
                        exclude_normal: true,
                    },
                },
                DetectionRuleSpec::ClassConfidence {
                    id: "class_confidence".into(),
                    output: "class_probs".into(),
                    attack: AttackMappingSpec::PredictedClass {
                        output: "class_probs".into(),
                        exclude_normal: true,
                    },
                },
            ],
            labels: BTreeMap::from([
                (
                    "0".into(),
                    LabelSpec {
                        name: "Bot".into(),
                        confirmations: Some(1),
                        playbook: None,
                    },
                ),
                (
                    "7".into(),
                    LabelSpec {
                        name: "Normal".into(),
                        confirmations: None,
                        playbook: None,
                    },
                ),
            ]),
            alert_rules: vec![AlertRuleSpec {
                condition: "anomaly > threshold".into(),
                source_label: "anomaly".into(),
            }],
        }
    }

    #[test]
    fn load_config_accepts_manifest_sidecar_pair() {
        let manifest = test_manifest();
        let tmp = env::temp_dir().join("netguardia-v1-config-loader");
        fs::create_dir_all(&tmp).unwrap();
        let manifest_path = tmp.join("manifest.yaml");
        let sidecar_path = tmp.join("sidecar.json");
        let mut f = fs::File::create(&sidecar_path).unwrap();
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
            classifier_feature_names: vec!["flow_duration".into(), "fwd_packets".into(), "ae_anomaly_score".into()],
            minmax_params: HashMap::new(),
            robust_params: HashMap::new(),
            quantile_params: HashMap::new(),
        };
        f.write_all(serde_json::to_string(&sidecar).unwrap().as_bytes())
            .unwrap();
        fs::write(&manifest_path, serde_yaml_ng::to_string(&manifest).unwrap()).unwrap();
        let loader = FsModelConfigLoader;
        let (cfg, loaded) = loader
            .load_manifest_with_sidecar(&manifest_path)
            .expect("load v1 manifest + sidecar");
        assert_eq!(loaded.name, "test");
        assert_eq!(
            cfg.ae_feature_names,
            vec!["flow_duration".to_string(), "fwd_packets".to_string()]
        );
        assert_eq!(
            cfg.classifier_feature_names.last().map(String::as_str),
            Some("ae_anomaly_score")
        );
    }

    #[test]
    fn invalid_sidecar_numeric_values_are_rejected() {
        let mut cfg = MLInferenceConfig {
            ae_feature_names: vec!["flow_duration".into()],
            ae_clip_params: HashMap::from([("flow_duration".into(), ClipParams { lower: 0.0, upper: 1.0 })]),
            ae_scaler_mean: vec![0.0],
            ae_scaler_std: vec![1.0],
            ae_post_clip_min: -5.0,
            ae_post_clip_max: 5.0,
            classifier_feature_names: vec!["flow_duration".into()],
            minmax_params: HashMap::new(),
            robust_params: HashMap::new(),
            quantile_params: HashMap::new(),
        };
        cfg.ae_scaler_std[0] = -1.0;
        assert!(validate_config(&cfg).is_err());
    }
}
