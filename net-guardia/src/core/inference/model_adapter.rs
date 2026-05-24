use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use crate::domain::common::event::DetectionSource;
use crate::domain::detection::attack_type::{CanonicalAttackType, translate};
use crate::domain::detection::manifest::{
    DetectionRuleSpec, LabelSpec, OutputHeadSpec, PipelineOutputSpec, PreprocessingStep, StageInputSpec, StageKind,
};
use crate::domain::detection::model_source::{ModelInfo, ModelSourceStatus};
use crate::interface::detection::model_runtime::ModelRuntime;

pub type RunnableModel = dyn ModelRuntime;

#[derive(Clone)]
pub enum MLModelAdapter {
    Pipeline {
        stages: Vec<PipelineStageAdapter>,
        outputs: Vec<PipelineOutputSpec>,
        detection_rules: Vec<DetectionRuleSpec>,
        labels: BTreeMap<String, LabelSpec>,
        normal_label: String,
    },
}

#[derive(Clone)]
pub struct PipelineStageAdapter {
    pub id: String,
    pub kind: StageKind,
    pub model: Arc<RunnableModel>,
    pub batch_size: usize,
    pub n_features: usize,
    pub inputs: Vec<StageInputSpec>,
    pub preprocessing: Vec<PreprocessingStep>,
    pub output_heads: Vec<OutputHeadSpec>,
}

impl MLModelAdapter {
    pub fn confirmations_for(&self, attack_type: CanonicalAttackType) -> Option<usize> {
        match self {
            Self::Pipeline { labels, .. } => confirmations_from_labels(labels, attack_type),
        }
    }
}

fn confirmations_from_labels(labels: &BTreeMap<String, LabelSpec>, attack_type: CanonicalAttackType) -> Option<usize> {
    labels
        .values()
        .find(|spec| translate(DetectionSource::ML, &spec.name) == attack_type)
        .and_then(|spec| spec.confirmations)
}

#[derive(Clone)]
pub enum ModelSourceState {
    Dormant,
    Active {
        adapter: MLModelAdapter,
        info: ModelInfo,
    },
    Error {
        msg: String,
        since: SystemTime,
        last_attempted_path: Option<PathBuf>,
    },
}

impl ModelSourceState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub fn to_status(&self) -> ModelSourceStatus {
        match self {
            Self::Dormant => ModelSourceStatus::Dormant,
            Self::Active { info, .. } => ModelSourceStatus::Active { info: info.clone() },
            Self::Error {
                msg,
                since,
                last_attempted_path,
            } => ModelSourceStatus::Error {
                msg: msg.clone(),
                since_secs: since
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                last_attempted_path: last_attempted_path.as_ref().map(|p| p.display().to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn dormant_state_serializes_to_dormant_status() {
        let state = ModelSourceState::Dormant;
        let status = state.to_status();
        assert!(status.is_dormant());
    }

    fn sample_labels() -> BTreeMap<String, LabelSpec> {
        let mut m = BTreeMap::new();
        m.insert(
            "0".into(),
            LabelSpec {
                name: "Bot".into(),
                confirmations: Some(1),
                playbook: None,
            },
        );
        m.insert(
            "4".into(),
            LabelSpec {
                name: "DoS/DDoS".into(),
                confirmations: Some(2),
                playbook: None,
            },
        );
        m.insert(
            "7".into(),
            LabelSpec {
                name: "Normal".into(),
                confirmations: None,
                playbook: None,
            },
        );
        m
    }

    #[test]
    fn confirmations_lookup_hits_exact_name() {
        let labels = sample_labels();
        assert_eq!(
            confirmations_from_labels(&labels, CanonicalAttackType::BotActivity),
            Some(1)
        );
        assert_eq!(
            confirmations_from_labels(&labels, CanonicalAttackType::DosDdos),
            Some(2)
        );
    }

    #[test]
    fn confirmations_lookup_is_case_insensitive() {
        let labels = sample_labels();
        assert_eq!(
            confirmations_from_labels(&labels, CanonicalAttackType::BotActivity),
            Some(1)
        );
        assert_eq!(
            confirmations_from_labels(&labels, CanonicalAttackType::DosDdos),
            Some(2)
        );
    }

    #[test]
    fn confirmations_lookup_label_without_override_returns_none() {
        let labels = sample_labels();
        assert_eq!(confirmations_from_labels(&labels, CanonicalAttackType::Unknown), None);
    }

    #[test]
    fn confirmations_lookup_unknown_name_returns_none() {
        let labels = sample_labels();
        assert_eq!(confirmations_from_labels(&labels, CanonicalAttackType::Exploit), None);
    }

    #[test]
    fn confirmations_lookup_empty_labels_returns_none() {
        let labels = BTreeMap::new();
        assert_eq!(
            confirmations_from_labels(&labels, CanonicalAttackType::BotActivity),
            None
        );
    }

    #[test]
    fn error_state_preserves_details() {
        let state = ModelSourceState::Error {
            msg: "shape mismatch".to_string(),
            since: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            last_attempted_path: Some(PathBuf::from("models/bad.onnx")),
        };
        let status = state.to_status();
        match status {
            ModelSourceStatus::Error {
                msg,
                since_secs,
                last_attempted_path,
            } => {
                assert_eq!(msg, "shape mismatch");
                assert_eq!(since_secs, 1_700_000_000);
                assert_eq!(last_attempted_path.as_deref(), Some("models/bad.onnx"));
            }
            _ => panic!("expected Error"),
        }
    }
}
