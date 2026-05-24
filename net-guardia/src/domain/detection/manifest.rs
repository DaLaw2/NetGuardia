use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::domain::detection::error::MLError;
use crate::domain::detection::feature_extractor::feature_registry_names;

pub const RUNTIME_ADAPTER_PIPELINE: &str = "pipeline";
pub const MANIFEST_VERSION: u32 = 1;
pub const RUNTIME_ADAPTERS: &[&str] = &[RUNTIME_ADAPTER_PIPELINE];
pub const REQUIRED_MANIFEST_SECTIONS: &[&str] = &[
    "runtime",
    "artifacts",
    "stages",
    "outputs",
    "detection_rules",
    "labels",
    "alert_rules",
];
pub const PREPROCESSING_TYPES: &[&str] = &[
    "standard_scaler",
    "minmax_scaler",
    "robust_scaler",
    "log_transform",
    "clip",
    "quantile",
];
pub const OUTPUT_SEMANTICS: &[&str] = &[
    "anomaly_score",
    "binary",
    "multiclass",
    "multilabel",
    "regression",
    "passthrough",
];
pub const OUTPUT_ROLES: &[&str] = &[
    "anomaly_score",
    "binary_score",
    "class_probabilities",
    "c2_score",
    "embedding",
    "ignore",
];
pub const DETECTION_RULE_TYPES: &[&str] = &["threshold", "class_confidence"];
pub const ATTACK_MAPPING_SOURCES: &[&str] = &["predicted_class", "fixed_label"];
pub const ARTIFACT_KINDS: &[&str] = &["onnx", "sidecar"];
pub const STAGE_KINDS: &[&str] = &["autoencoder", "classifier", "generic"];
pub const STAGE_INPUT_SOURCES: &[&str] = &["feature", "stage_output"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelManifest {
    pub name: String,
    pub version: u32,
    pub runtime: RuntimeSpec,
    pub artifacts: Vec<ArtifactSpec>,
    pub stages: Vec<StageSpec>,
    pub outputs: Vec<PipelineOutputSpec>,
    pub detection_rules: Vec<DetectionRuleSpec>,
    pub labels: BTreeMap<String, LabelSpec>,
    pub alert_rules: Vec<AlertRuleSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    pub pipeline_mode: String,
    pub normal_label: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub id: String,
    pub file: String,
    pub kind: ArtifactKind,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Onnx,
    Sidecar,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageSpec {
    pub id: String,
    pub kind: StageKind,
    pub model_file: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub inputs: Vec<StageInputSpec>,
    #[serde(default)]
    pub preprocessing: Vec<PreprocessingStep>,
    #[serde(default)]
    pub output_heads: Vec<OutputHeadSpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    Autoencoder,
    Classifier,
    Generic,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageInputSpec {
    pub name: String,
    pub source: StageInputSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageInputSource {
    Feature,
    StageOutput,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineOutputSpec {
    pub stage: String,
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub role: OutputRole,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputRole {
    AnomalyScore,
    BinaryScore,
    ClassProbabilities,
    C2Score,
    Embedding,
    Ignore,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreprocessingStep {
    StandardScaler {
        sidecar: String,
    },
    MinMaxScaler {
        sidecar: String,
    },
    RobustScaler {
        sidecar: String,
    },
    LogTransform {
        #[serde(default = "default_log_offset")]
        offset: f32,
    },
    Clip {
        min: f32,
        max: f32,
    },
    Quantile {
        sidecar: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputSemantic {
    AnomalyScore,
    Binary,
    Multiclass,
    Multilabel,
    Regression,
    Passthrough,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputHeadSpec {
    pub name: String,
    pub index: usize,
    pub shape: Vec<String>,
    pub semantic: OutputSemantic,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<f32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectionRuleSpec {
    Threshold {
        id: String,
        output: String,
        attack: AttackMappingSpec,
    },
    ClassConfidence {
        id: String,
        output: String,
        attack: AttackMappingSpec,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttackMappingSpec {
    PredictedClass { output: String, exclude_normal: bool },
    FixedLabel { label: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSpec {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playbook: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRuleSpec {
    pub condition: String,
    pub source_label: String,
}

impl ModelManifest {
    pub fn validate(&self, path: &Path) -> Result<(), MLError> {
        if self.version != MANIFEST_VERSION {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!("version must be {MANIFEST_VERSION} (got {})", self.version),
            ));
        }
        if self.name.trim().is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "name is empty".to_string(),
            ));
        }
        if self.stages.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "stages is empty".to_string(),
            ));
        }
        if self.outputs.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "outputs is empty".to_string(),
            ));
        }

        self.validate_runtime(path)?;
        self.validate_artifacts(path)?;
        self.validate_stages(path)?;
        self.validate_stage_graph(path)?;
        self.validate_stage_features(path)?;
        self.validate_pipeline_outputs(path)?;
        self.validate_labels(path)?;
        self.validate_detection_rules(path)?;
        self.validate_alert_rules(path)?;
        Ok(())
    }

    pub fn runtime_adapter(&self) -> &'static str {
        RUNTIME_ADAPTER_PIPELINE
    }

    pub fn runtime_feature_count(&self) -> usize {
        self.stages.first().map(|stage| stage.inputs.len()).unwrap_or(0)
    }

    pub fn primary_scaler_sidecar(&self) -> Option<&str> {
        self.stages.iter().find_map(|stage| {
            stage.preprocessing.iter().find_map(|step| match step {
                PreprocessingStep::StandardScaler { sidecar }
                | PreprocessingStep::MinMaxScaler { sidecar }
                | PreprocessingStep::RobustScaler { sidecar }
                | PreprocessingStep::Quantile { sidecar } => Some(sidecar.as_str()),
                _ => None,
            })
        })
    }

    pub fn stage_by_id(&self, id: &str) -> Option<&StageSpec> {
        self.stages.iter().find(|stage| stage.id == id)
    }

    pub fn topological_stages(&self) -> Result<Vec<&StageSpec>, MLError> {
        let mut ordered = Vec::with_capacity(self.stages.len());
        let mut emitted = HashSet::new();
        loop {
            let before = ordered.len();
            for stage in &self.stages {
                if emitted.contains(&stage.id) {
                    continue;
                }
                if stage.depends_on.iter().all(|id| emitted.contains(id)) {
                    emitted.insert(stage.id.clone());
                    ordered.push(stage);
                }
            }
            if ordered.len() == self.stages.len() {
                return Ok(ordered);
            }
            if ordered.len() == before {
                return Err(MLError::ManifestInvalid(
                    PathBuf::new(),
                    "stages contain a dependency cycle or unresolved dependency".to_string(),
                ));
            }
        }
    }

    fn validate_runtime(&self, path: &Path) -> Result<(), MLError> {
        if self.runtime.pipeline_mode != "dag" {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!("runtime.pipeline_mode must be dag (got {})", self.runtime.pipeline_mode),
            ));
        }
        if self.runtime.normal_label.trim().is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "runtime.normal_label is empty".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_artifacts(&self, path: &Path) -> Result<(), MLError> {
        if self.artifacts.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "artifacts is empty".to_string(),
            ));
        }
        let mut seen_ids = Vec::with_capacity(self.artifacts.len());
        let mut seen_files: Vec<Vec<String>> = Vec::with_capacity(self.artifacts.len());
        for artifact in &self.artifacts {
            if artifact.id.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    "artifact id is empty".to_string(),
                ));
            }
            if seen_ids.iter().any(|id| id == &artifact.id) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate artifact id '{}'", artifact.id),
                ));
            }
            seen_ids.push(artifact.id.clone());
            validate_relative_artifact_path(path, &format!("artifacts[{}].file", artifact.id), &artifact.file)?;
            validate_artifact_not_manifest_path(path, &format!("artifacts[{}].file", artifact.id), &artifact.file)?;
            let components = normalized_artifact_components(&artifact.file);
            if seen_files.iter().any(|existing| existing == &components) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate artifact file '{}'", artifact.file),
                ));
            }
            seen_files.push(components);
        }
        Ok(())
    }

    fn validate_stages(&self, path: &Path) -> Result<(), MLError> {
        let mut seen_ids = Vec::with_capacity(self.stages.len());
        let artifact_files: HashSet<&str> = self.artifacts.iter().map(|artifact| artifact.file.as_str()).collect();
        for stage in &self.stages {
            if stage.id.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    "stage id is empty".to_string(),
                ));
            }
            if seen_ids.iter().any(|id| id == &stage.id) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate stage id '{}'", stage.id),
                ));
            }
            seen_ids.push(stage.id.clone());
            validate_relative_artifact_path(path, &format!("stages[{}].model_file", stage.id), &stage.model_file)?;
            validate_artifact_not_manifest_path(path, &format!("stages[{}].model_file", stage.id), &stage.model_file)?;
            if !artifact_files.is_empty() && !artifact_files.contains(stage.model_file.as_str()) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' model_file is not declared in artifacts", stage.id),
                ));
            }
            if let Some(artifact) = self.artifacts.iter().find(|artifact| artifact.file == stage.model_file)
                && artifact.kind != ArtifactKind::Onnx
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' model_file must reference an onnx artifact", stage.id),
                ));
            }
            if stage.inputs.is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' inputs is empty", stage.id),
                ));
            }
            if stage.output_heads.is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' output_heads is empty", stage.id),
                ));
            }
            self.validate_stage_inputs(path, stage)?;
            self.validate_preprocessing(path, &stage.id, &stage.preprocessing)?;
            for step in &stage.preprocessing {
                if let Some(sidecar) = preprocessing_sidecar(step) {
                    let Some(artifact) = self.artifacts.iter().find(|artifact| artifact.file == sidecar) else {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "stage '{}' preprocessing sidecar is not declared in artifacts",
                                stage.id
                            ),
                        ));
                    };
                    if artifact.kind != ArtifactKind::Sidecar {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "stage '{}' preprocessing sidecar must reference a sidecar artifact",
                                stage.id
                            ),
                        ));
                    }
                }
            }
            self.validate_outputs(path, &stage.id, &stage.output_heads)?;
        }
        Ok(())
    }

    fn validate_stage_inputs(&self, path: &Path, stage: &StageSpec) -> Result<(), MLError> {
        let mut seen = Vec::with_capacity(stage.inputs.len());
        for input in &stage.inputs {
            if input.name.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' has an input with empty name", stage.id),
                ));
            }
            if seen.iter().any(|name| name == &input.name) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("stage '{}' has duplicate input '{}'", stage.id, input.name),
                ));
            }
            seen.push(input.name.clone());
            match input.source {
                StageInputSource::Feature => {
                    if input.stage.is_some() || input.output.is_some() {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "stage '{}' feature input '{}' must not declare stage/output",
                                stage.id, input.name
                            ),
                        ));
                    }
                }
                StageInputSource::StageOutput => {
                    if input.stage.as_ref().is_none_or(|value| value.trim().is_empty())
                        || input.output.as_ref().is_none_or(|value| value.trim().is_empty())
                    {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "stage '{}' stage_output input '{}' requires stage and output",
                                stage.id, input.name
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_stage_graph(&self, path: &Path) -> Result<(), MLError> {
        for stage in &self.stages {
            for dep in &stage.depends_on {
                if self.stage_by_id(dep).is_none() {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        format!("stage '{}' depends on unknown stage '{dep}'", stage.id),
                    ));
                }
                if dep == &stage.id {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        format!("stage '{}' depends on itself", stage.id),
                    ));
                }
            }
        }
        self.topological_stages()
            .map(|_| ())
            .map_err(|e| MLError::ManifestInvalid(path.to_path_buf(), e.to_string()))
    }

    fn validate_stage_features(&self, path: &Path) -> Result<(), MLError> {
        let mut available: HashSet<String> = feature_registry_names()
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        for stage in self.topological_stages()? {
            for input in &stage.inputs {
                match input.source {
                    StageInputSource::Feature => {
                        if !available.contains(&input.name) {
                            return Err(MLError::UnknownFeature(input.name.clone()));
                        }
                    }
                    StageInputSource::StageOutput => {
                        let Some(source_stage) = input.stage.as_ref() else {
                            return Err(MLError::ManifestInvalid(
                                path.to_path_buf(),
                                format!("stage '{}' input '{}' missing source stage", stage.id, input.name),
                            ));
                        };
                        let Some(source_output) = input.output.as_ref() else {
                            return Err(MLError::ManifestInvalid(
                                path.to_path_buf(),
                                format!("stage '{}' input '{}' missing source output", stage.id, input.name),
                            ));
                        };
                        let key = stage_output_key(source_stage, source_output);
                        if !available.contains(&key) {
                            return Err(MLError::ManifestInvalid(
                                path.to_path_buf(),
                                format!(
                                    "stage '{}' input '{}' references unavailable output '{}.{}'",
                                    stage.id, input.name, source_stage, source_output
                                ),
                            ));
                        }
                    }
                }
            }
            for output in &stage.output_heads {
                available.insert(stage_output_key(&stage.id, &output.name));
            }
        }
        Ok(())
    }

    fn validate_pipeline_outputs(&self, path: &Path) -> Result<(), MLError> {
        let mut seen_refs = Vec::with_capacity(self.outputs.len());
        for output in &self.outputs {
            let Some(stage) = self.stage_by_id(&output.stage) else {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("pipeline output references unknown stage '{}'", output.stage),
                ));
            };
            if !stage.output_heads.iter().any(|head| head.name == output.output) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "pipeline output references unknown output '{}.{}'",
                        output.stage, output.output
                    ),
                ));
            }
            if let Some(alias) = output.alias.as_ref()
                && alias.trim().is_empty()
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "pipeline output '{}.{}' has an empty alias",
                        output.stage, output.output
                    ),
                ));
            }
            let reference = output_reference(output);
            if seen_refs.iter().any(|seen| seen == &reference) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate pipeline output reference '{reference}'"),
                ));
            }
            seen_refs.push(reference);
            let Some(head) = stage.output_heads.iter().find(|head| head.name == output.output) else {
                continue;
            };
            self.validate_output_role(path, output, head)?;
        }
        Ok(())
    }

    fn validate_output_role(
        &self,
        path: &Path,
        output: &PipelineOutputSpec,
        head: &OutputHeadSpec,
    ) -> Result<(), MLError> {
        let is_matrix = output_semantic_is_matrix(&head.semantic);
        match output.role {
            OutputRole::ClassProbabilities | OutputRole::Embedding if !is_matrix => {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "pipeline output '{}' role {:?} requires a matrix output semantic",
                        output_reference(output),
                        output.role
                    ),
                ));
            }
            OutputRole::AnomalyScore | OutputRole::BinaryScore | OutputRole::C2Score if is_matrix => {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "pipeline output '{}' role {:?} requires a scalar output semantic",
                        output_reference(output),
                        output.role
                    ),
                ));
            }
            OutputRole::ClassProbabilities
                if !matches!(head.semantic, OutputSemantic::Multiclass | OutputSemantic::Multilabel) =>
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "pipeline output '{}' role class_probabilities requires multiclass or multilabel semantic",
                        output_reference(output)
                    ),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_preprocessing(&self, path: &Path, model_id: &str, steps: &[PreprocessingStep]) -> Result<(), MLError> {
        for (idx, step) in steps.iter().enumerate() {
            match step {
                PreprocessingStep::StandardScaler { sidecar }
                | PreprocessingStep::MinMaxScaler { sidecar }
                | PreprocessingStep::RobustScaler { sidecar }
                | PreprocessingStep::Quantile { sidecar } => {
                    validate_relative_artifact_path(
                        path,
                        &format!("models[{model_id}].preprocessing[{idx}]"),
                        sidecar,
                    )?;
                    validate_artifact_not_manifest_path(
                        path,
                        &format!("models[{model_id}].preprocessing[{idx}]"),
                        sidecar,
                    )?;
                }
                PreprocessingStep::LogTransform { offset } => {
                    if !offset.is_finite() || *offset < 0.0 {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "models[{model_id}].preprocessing[{idx}].offset must be finite and >= 0 (got {offset})"
                            ),
                        ));
                    }
                }
                PreprocessingStep::Clip { min, max } => {
                    if !min.is_finite() || !max.is_finite() || min > max {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!(
                                "models[{model_id}].preprocessing[{idx}] clip range must be finite and ordered lower <= upper (got {min}..{max})"
                            ),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_outputs(&self, path: &Path, model_id: &str, outputs: &[OutputHeadSpec]) -> Result<(), MLError> {
        let mut seen_names = Vec::with_capacity(outputs.len());
        let mut seen_indexes = Vec::with_capacity(outputs.len());
        for output in outputs {
            if output.name.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("model '{model_id}' has an output with empty name"),
                ));
            }
            if output.shape.is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("model '{model_id}' output '{}' shape is empty", output.name),
                ));
            }
            for dim in &output.shape {
                validate_output_shape_dim(path, model_id, &output.name, dim)?;
            }
            if seen_names.iter().any(|name| name == &output.name) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("model '{model_id}' has duplicate output name '{}'", output.name),
                ));
            }
            seen_names.push(output.name.clone());
            if seen_indexes.iter().any(|index| index == &output.index) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("model '{model_id}' has duplicate output index '{}'", output.index),
                ));
            }
            seen_indexes.push(output.index);
            if let Some(value) = output.threshold
                && !(value.is_finite() && value >= 0.0)
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "model '{model_id}' output '{}' threshold must be finite and >= 0 (got {value})",
                        output.name
                    ),
                ));
            }
            if let Some(value) = output.min_confidence
                && !(value.is_finite() && (0.0..=1.0).contains(&value))
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!(
                        "model '{model_id}' output '{}' min_confidence must be finite and in [0, 1] (got {value})",
                        output.name
                    ),
                ));
            }
        }
        Ok(())
    }

    fn validate_detection_rules(&self, path: &Path) -> Result<(), MLError> {
        if self.detection_rules.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "detection_rules is empty".to_string(),
            ));
        }
        let mut seen_ids = Vec::with_capacity(self.detection_rules.len());
        for rule in &self.detection_rules {
            let id = rule.id();
            if id.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    "detection rule id is empty".to_string(),
                ));
            }
            if seen_ids.iter().any(|seen| seen == id) {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("duplicate detection rule id '{id}'"),
                ));
            }
            seen_ids.push(id.to_string());
            match rule {
                DetectionRuleSpec::Threshold { output, attack, .. } => {
                    let (_, head) = self.pipeline_output_head(path, output)?;
                    if output_semantic_is_matrix(&head.semantic) {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!("detection rule '{id}' threshold output '{output}' must be scalar"),
                        ));
                    }
                    if head.threshold.is_none() {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!("detection rule '{id}' threshold output '{output}' requires threshold"),
                        ));
                    }
                    self.validate_attack_mapping(path, id, attack)?;
                }
                DetectionRuleSpec::ClassConfidence { output, attack, .. } => {
                    let (_, head) = self.pipeline_output_head(path, output)?;
                    if !output_semantic_is_matrix(&head.semantic) {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!("detection rule '{id}' class output '{output}' must be matrix"),
                        ));
                    }
                    if head.min_confidence.is_none() {
                        return Err(MLError::ManifestInvalid(
                            path.to_path_buf(),
                            format!("detection rule '{id}' class output '{output}' requires min_confidence"),
                        ));
                    }
                    self.validate_attack_mapping(path, id, attack)?;
                }
            }
        }
        Ok(())
    }

    fn validate_attack_mapping(&self, path: &Path, rule_id: &str, attack: &AttackMappingSpec) -> Result<(), MLError> {
        match attack {
            AttackMappingSpec::PredictedClass { output, .. } => {
                let (pipeline_output, head) = self.pipeline_output_head(path, output)?;
                if !output_semantic_is_matrix(&head.semantic) || pipeline_output.role != OutputRole::ClassProbabilities
                {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        format!(
                            "detection rule '{rule_id}' predicted_class output '{output}' must be a class_probabilities output"
                        ),
                    ));
                }
            }
            AttackMappingSpec::FixedLabel { label } => {
                if !self.labels.values().any(|spec| spec.name.eq_ignore_ascii_case(label)) {
                    return Err(MLError::ManifestInvalid(
                        path.to_path_buf(),
                        format!("detection rule '{rule_id}' fixed label '{label}' is not declared in labels"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn pipeline_output_head(
        &self,
        path: &Path,
        reference: &str,
    ) -> Result<(&PipelineOutputSpec, &OutputHeadSpec), MLError> {
        let Some(output) = self.pipeline_output_by_ref(reference) else {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!("pipeline output reference '{reference}' is not declared in outputs"),
            ));
        };
        let Some(stage) = self.stage_by_id(&output.stage) else {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!(
                    "pipeline output reference '{reference}' uses unknown stage '{}'",
                    output.stage
                ),
            ));
        };
        let Some(head) = stage.output_heads.iter().find(|head| head.name == output.output) else {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                format!(
                    "pipeline output reference '{reference}' uses unknown output '{}.{}'",
                    output.stage, output.output
                ),
            ));
        };
        Ok((output, head))
    }

    pub fn pipeline_output_by_ref(&self, reference: &str) -> Option<&PipelineOutputSpec> {
        self.outputs.iter().find(|output| output_matches_ref(output, reference))
    }

    fn validate_labels(&self, path: &Path) -> Result<(), MLError> {
        if self.labels.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "labels is empty".to_string(),
            ));
        }
        let mut seen: Vec<String> = Vec::with_capacity(self.labels.len());
        for (key, spec) in &self.labels {
            if key.parse::<usize>().is_err() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("label key '{key}' must be a non-negative classifier output index"),
                ));
            }
            if let Some(n) = spec.confirmations
                && n == 0
            {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("label '{}' has confirmations: 0 (must be >= 1)", spec.name),
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

    fn validate_alert_rules(&self, path: &Path) -> Result<(), MLError> {
        if self.alert_rules.is_empty() {
            return Err(MLError::ManifestInvalid(
                path.to_path_buf(),
                "alert_rules is empty".to_string(),
            ));
        }
        for (idx, rule) in self.alert_rules.iter().enumerate() {
            if rule.condition.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("alert_rules[{idx}].condition is empty"),
                ));
            }
            if rule.source_label.trim().is_empty() {
                return Err(MLError::ManifestInvalid(
                    path.to_path_buf(),
                    format!("alert_rules[{idx}].source_label is empty"),
                ));
            }
        }
        Ok(())
    }

    pub fn resolve_relative(manifest_path: &Path, relative: &str) -> PathBuf {
        manifest_path.parent().unwrap_or_else(|| Path::new(".")).join(relative)
    }
}

impl DetectionRuleSpec {
    pub fn id(&self) -> &str {
        match self {
            Self::Threshold { id, .. } | Self::ClassConfidence { id, .. } => id,
        }
    }
}

fn default_log_offset() -> f32 {
    1.0
}

pub fn preprocessing_sidecar(step: &PreprocessingStep) -> Option<&str> {
    match step {
        PreprocessingStep::StandardScaler { sidecar }
        | PreprocessingStep::MinMaxScaler { sidecar }
        | PreprocessingStep::RobustScaler { sidecar }
        | PreprocessingStep::Quantile { sidecar } => Some(sidecar),
        PreprocessingStep::LogTransform { .. } | PreprocessingStep::Clip { .. } => None,
    }
}

pub fn stage_output_key(stage: &str, output: &str) -> String {
    format!("{stage}.{output}")
}

pub fn output_reference(output: &PipelineOutputSpec) -> String {
    output
        .alias
        .as_ref()
        .filter(|alias| !alias.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| stage_output_key(&output.stage, &output.output))
}

pub fn output_matches_ref(output: &PipelineOutputSpec, reference: &str) -> bool {
    output.alias.as_deref() == Some(reference) || stage_output_key(&output.stage, &output.output) == reference
}

pub fn output_semantic_is_matrix(semantic: &OutputSemantic) -> bool {
    matches!(semantic, OutputSemantic::Multiclass | OutputSemantic::Multilabel)
}

fn validate_output_shape_dim(path: &Path, model_id: &str, output_name: &str, dim: &str) -> Result<(), MLError> {
    let trimmed = dim.trim();
    if trimmed.is_empty() {
        return Err(MLError::ManifestInvalid(
            path.to_path_buf(),
            format!("model '{model_id}' output '{output_name}' has an empty shape dimension"),
        ));
    }
    if trimmed.parse::<usize>().is_ok() {
        return Ok(());
    }
    if trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Ok(());
    }
    Err(MLError::ManifestInvalid(
        path.to_path_buf(),
        format!("model '{model_id}' output '{output_name}' has invalid shape dimension '{dim}'"),
    ))
}

fn validate_relative_artifact_path(manifest_path: &Path, field: &str, value: &str) -> Result<(), MLError> {
    if value.is_empty() {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            format!("{field} is empty"),
        ));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            format!("{field} must be relative, not absolute: {value:?}"),
        ));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            format!("{field} must not contain root, current-directory, or parent-directory segments: {value:?}"),
        ));
    }
    Ok(())
}

fn validate_artifact_not_manifest_path(manifest_path: &Path, field: &str, value: &str) -> Result<(), MLError> {
    let Some(manifest_file_name) = manifest_path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let components = normalized_artifact_components(value);
    if components.len() == 1 && components[0] == manifest_file_name {
        return Err(MLError::ManifestInvalid(
            manifest_path.to_path_buf(),
            format!("{field} must not point at the manifest file itself: {value:?}"),
        ));
    }
    Ok(())
}

fn normalized_artifact_components(value: &str) -> Vec<String> {
    Path::new(value)
        .components()
        .filter_map(|component| match component {
            Component::Normal(s) => s.to_str().map(|s| s.to_string()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_MANIFEST: &str = r#"
name: netguardia-v1
version: 1
runtime:
  pipeline_mode: dag
  normal_label: Normal
artifacts:
  - id: ae_onnx
    file: deep_autoencoder.onnx
    kind: onnx
  - id: classifier_onnx
    file: classifier.onnx
    kind: onnx
  - id: sidecar
    file: inference_config.json
    kind: sidecar
stages:
  - id: anomaly_detector
    kind: autoencoder
    model_file: deep_autoencoder.onnx
    inputs:
      - { name: flow_duration, source: feature }
      - { name: fwd_packets, source: feature }
    preprocessing:
      - type: standard_scaler
        sidecar: inference_config.json
      - type: clip
        min: -5.0
        max: 5.0
    output_heads:
      - name: ae_anomaly_score
        index: 0
        shape: [1]
        semantic: anomaly_score
        threshold: 0.23
  - id: classifier
    kind: classifier
    model_file: classifier.onnx
    depends_on:
      - anomaly_detector
    inputs:
      - { name: flow_duration, source: feature }
      - { name: fwd_packets, source: feature }
      - name: ae_anomaly_score
        source: stage_output
        stage: anomaly_detector
        output: ae_anomaly_score
    output_heads:
      - name: anomaly
        index: 0
        shape: [1]
        semantic: binary
        threshold: 0.91
      - name: class_probs
        index: 1
        shape: [10]
        semantic: multiclass
        min_confidence: 0.4
outputs:
  - stage: anomaly_detector
    output: ae_anomaly_score
    alias: ae_anomaly_score
    role: anomaly_score
  - stage: classifier
    output: anomaly
    alias: anomaly
    role: binary_score
  - stage: classifier
    output: class_probs
    alias: class_probs
    role: class_probabilities
detection_rules:
  - id: anomaly_threshold
    type: threshold
    output: anomaly
    attack:
      source: predicted_class
      output: class_probs
      exclude_normal: true
  - id: class_confidence
    type: class_confidence
    output: class_probs
    attack:
      source: predicted_class
      output: class_probs
      exclude_normal: true
labels:
  "0": { name: Bot, confirmations: 1 }
  "7": { name: Normal }
alert_rules:
  - condition: "anomaly > threshold"
    source_label: anomaly
"#;

    #[test]
    fn parse_v1_manifest() {
        let parsed: ModelManifest = serde_yaml_ng::from_str(V1_MANIFEST).expect("parse");
        parsed.validate(Path::new("/tmp/manifest.yaml")).expect("valid v1");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.runtime_adapter(), RUNTIME_ADAPTER_PIPELINE);
        assert_eq!(parsed.runtime_feature_count(), 2);
        assert_eq!(parsed.primary_scaler_sidecar(), Some("inference_config.json"));
    }

    #[test]
    fn reject_invalid_version() {
        let yaml = V1_MANIFEST.replace("version: 1", "version: 2");
        let parsed: ModelManifest = serde_yaml_ng::from_str(&yaml).expect("parse");
        let err = parsed
            .validate(Path::new("/tmp/manifest.yaml"))
            .expect_err("should reject version");
        assert!(err.to_string().contains("version must be 1"));
    }

    #[test]
    fn reject_unknown_feature() {
        let yaml = V1_MANIFEST.replace("flow_duration", "not_a_real_feature");
        let parsed: ModelManifest = serde_yaml_ng::from_str(&yaml).expect("parse");
        let err = parsed
            .validate(Path::new("/tmp/manifest.yaml"))
            .expect_err("should reject unknown feature");
        assert!(err.to_string().contains("Unknown feature"));
    }

    #[test]
    fn reject_stage_cycle() {
        let yaml = V1_MANIFEST.replace(
            "depends_on:\n      - anomaly_detector",
            "depends_on:\n      - anomaly_detector\n      - classifier",
        );
        let parsed: ModelManifest = serde_yaml_ng::from_str(&yaml).expect("parse");
        let err = parsed
            .validate(Path::new("/tmp/manifest.yaml"))
            .expect_err("should reject cycle");
        assert!(err.to_string().contains("depends on itself"));
    }
}
