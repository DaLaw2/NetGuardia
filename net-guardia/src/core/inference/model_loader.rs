use std::path::Path;
use std::time::Duration;

use crate::core::inference::model_adapter::{MLModelAdapter, PipelineStageAdapter};
use crate::domain::detection::error::MLError;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;

pub fn build_adapter(
    manifest: &ModelManifest,
    manifest_path: Option<&Path>,
    inference_config: &MLInferenceConfig,
    batch_size: usize,
    onnx_load_timeout: Duration,
    runtime_loader: &dyn ModelRuntimeLoader,
    artifact_resolver: &dyn ModelArtifactResolver,
) -> Result<MLModelAdapter, MLError> {
    let ordered = manifest.topological_stages()?;
    let mut stages = Vec::with_capacity(ordered.len());
    for stage in ordered {
        let path = artifact_resolver.resolve_model_path(manifest_path, &stage.model_file);
        let n_features = stage.inputs.len();
        let runtime = runtime_loader.load(&path, &stage.model_file, n_features, batch_size, onnx_load_timeout)?;
        stages.push(PipelineStageAdapter {
            id: stage.id.clone(),
            kind: stage.kind.clone(),
            model: runtime,
            batch_size,
            n_features,
            inputs: stage.inputs.clone(),
            preprocessing: stage.preprocessing.clone(),
            output_heads: stage.output_heads.clone(),
        });
    }
    let labels = manifest.labels.clone();
    let _ = inference_config;
    Ok(MLModelAdapter::Pipeline {
        stages,
        outputs: manifest.outputs.clone(),
        detection_rules: manifest.detection_rules.clone(),
        labels,
        normal_label: manifest.runtime.normal_label.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::domain::detection::manifest::{
        ArtifactKind, ArtifactSpec, AttackMappingSpec, DetectionRuleSpec, LabelSpec, OutputHeadSpec, OutputRole,
        OutputSemantic, PipelineOutputSpec, PreprocessingStep, RuntimeSpec, StageInputSource, StageInputSpec,
        StageKind, StageSpec,
    };
    use crate::domain::detection::ml_detection::ClipParams;
    use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
    use crate::interface::detection::model_runtime::{ModelRuntime, RuntimeTensor};

    struct FakeRuntime;

    impl ModelRuntime for FakeRuntime {
        fn run_stage_batch(
            &self,
            _rows: &[Vec<f32>],
            _batch_size: usize,
            _n_features: usize,
            _stage_kind: StageKind,
            _output_heads: &[OutputHeadSpec],
        ) -> Result<Vec<RuntimeTensor>, MLError> {
            Ok(Vec::new())
        }
    }

    struct FakeLoader;

    impl ModelRuntimeLoader for FakeLoader {
        fn load(
            &self,
            _model_path: &Path,
            _model_name: &str,
            _features: usize,
            _batch_size: usize,
            _timeout: Duration,
        ) -> Result<Arc<dyn ModelRuntime>, MLError> {
            Ok(Arc::new(FakeRuntime))
        }
    }

    struct FakeResolver;

    impl ModelArtifactResolver for FakeResolver {
        fn resolve_model_path(&self, manifest_path: Option<&Path>, relative_path: &str) -> PathBuf {
            match manifest_path {
                Some(path) => ModelManifest::resolve_relative(path, relative_path),
                None => PathBuf::from("models").join(relative_path),
            }
        }
    }

    #[test]
    fn build_adapter_pipeline_uses_runtime_loader() {
        let config = MLInferenceConfig {
            ae_feature_names: vec!["duration".to_string(), "bytes".to_string()],
            ae_clip_params: HashMap::from([
                ("duration".to_string(), ClipParams { lower: 0.0, upper: 1.0 }),
                ("bytes".to_string(), ClipParams { lower: 0.0, upper: 1.0 }),
            ]),
            ae_scaler_mean: vec![0.0, 0.0],
            ae_scaler_std: vec![1.0, 1.0],
            ae_post_clip_min: -5.0,
            ae_post_clip_max: 5.0,
            classifier_feature_names: vec!["duration".to_string(), "bytes".to_string(), "ae_score".to_string()],
            minmax_params: HashMap::new(),
            robust_params: HashMap::new(),
            quantile_params: HashMap::new(),
        };
        let manifest = ModelManifest {
            name: "test".to_string(),
            version: 1,
            runtime: RuntimeSpec {
                pipeline_mode: "dag".to_string(),
                normal_label: "Normal".to_string(),
            },
            artifacts: vec![
                ArtifactSpec {
                    id: "ae_onnx".to_string(),
                    file: "ae.onnx".to_string(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "classifier_onnx".to_string(),
                    file: "classifier.onnx".to_string(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "sidecar".to_string(),
                    file: "sidecar.json".to_string(),
                    kind: ArtifactKind::Sidecar,
                },
            ],
            stages: vec![
                StageSpec {
                    id: "ae".to_string(),
                    kind: StageKind::Autoencoder,
                    model_file: "ae.onnx".to_string(),
                    depends_on: vec![],
                    inputs: config
                        .ae_feature_names
                        .iter()
                        .map(|name| StageInputSpec {
                            name: name.clone(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        })
                        .collect(),
                    preprocessing: vec![PreprocessingStep::StandardScaler {
                        sidecar: "sidecar.json".to_string(),
                    }],
                    output_heads: vec![OutputHeadSpec {
                        name: "reconstruction_error".to_string(),
                        index: 0,
                        shape: vec!["1".to_string()],
                        semantic: OutputSemantic::AnomalyScore,
                        threshold: Some(0.5),
                        min_confidence: None,
                    }],
                },
                StageSpec {
                    id: "classifier".to_string(),
                    kind: StageKind::Classifier,
                    model_file: "classifier.onnx".to_string(),
                    depends_on: vec!["ae".to_string()],
                    inputs: vec![
                        StageInputSpec {
                            name: "duration".to_string(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "bytes".to_string(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "ae_anomaly_score".to_string(),
                            source: StageInputSource::StageOutput,
                            stage: Some("ae".to_string()),
                            output: Some("reconstruction_error".to_string()),
                        },
                    ],
                    preprocessing: vec![],
                    output_heads: vec![OutputHeadSpec {
                        name: "class_probs".to_string(),
                        index: 0,
                        shape: vec!["10".to_string()],
                        semantic: OutputSemantic::Multiclass,
                        threshold: None,
                        min_confidence: Some(0.4),
                    }],
                },
            ],
            outputs: vec![PipelineOutputSpec {
                stage: "classifier".to_string(),
                output: "class_probs".to_string(),
                alias: Some("class_probs".to_string()),
                role: OutputRole::ClassProbabilities,
            }],
            detection_rules: vec![DetectionRuleSpec::ClassConfidence {
                id: "class_confidence".to_string(),
                output: "class_probs".to_string(),
                attack: AttackMappingSpec::PredictedClass {
                    output: "class_probs".to_string(),
                    exclude_normal: true,
                },
            }],
            labels: BTreeMap::from([(
                "7".to_string(),
                LabelSpec {
                    name: "Normal".to_string(),
                    confirmations: None,
                    playbook: None,
                },
            )]),
            alert_rules: vec![],
        };

        let adapter = build_adapter(
            &manifest,
            Some(Path::new("models/manifest.yaml")),
            &config,
            8,
            Duration::from_secs(5),
            &FakeLoader,
            &FakeResolver,
        )
        .expect("build adapter");

        let MLModelAdapter::Pipeline { stages, .. } = adapter;
        assert_eq!(stages[0].n_features, 2);
        assert_eq!(stages[1].n_features, 3);
    }
}
