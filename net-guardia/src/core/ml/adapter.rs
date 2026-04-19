//! `MLModelAdapter` — the three ONNX adapter shapes the inference pipeline
//! understands, plus the wrapping `ModelSourceState` machine used inside
//! `Inference::models: ArcSwap<ModelSourceState>`.
//!
//! Day 1 is `Dormant` (no model loaded); the happy path is `Active { adapter,
//! info }`; failed loads park in `Error { msg, since, last_attempted_path }`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use super::manifest::LabelSpec;
use crate::model::detection::ml_detection::RunnableModel;
use crate::model::detection::model_source::{ModelInfo, ModelSourceStatus};

/// Compile-time sanity: `RunnableModel` must be `Send + Sync` because we
/// stuff it inside an `ArcSwap`. If a future `tract-onnx` upgrade silently
/// drops the bounds, this line stops compiling and we catch it before it
/// becomes a production data race.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RunnableModel>();
};

/// One of three adapter shapes. Each variant carries the RunnableModel(s)
/// it needs plus the metadata required to dispatch inference:
/// batch size, feature counts, label map (classifier / multi-task only).
#[derive(Clone)]
pub enum MLModelAdapter {
    /// Pure anomaly-detection autoencoder. Output is a single MSE-style
    /// reconstruction error per flow; classifier-less. v1 product main path.
    AutoencoderOnly {
        model: Arc<RunnableModel>,
        batch_size: usize,
        n_features: usize,
    },
    /// Single classifier, no AE. Output is a per-class softmax tensor.
    /// Labels come from the manifest's `labels` map; `normal_idx` is
    /// pre-resolved so `infer_batch` doesn't re-scan on every tick.
    ClassifierOnly {
        model: Arc<RunnableModel>,
        batch_size: usize,
        n_features: usize,
        labels: BTreeMap<String, LabelSpec>,
        normal_idx: Option<usize>,
    },
    /// AE + classifier in one adapter. Classifier consumes (ae_features, ae_score).
    /// Three output tensors: anomaly_score / class_probs / c2_score.
    MultiTask {
        ae: Arc<RunnableModel>,
        classifier: Arc<RunnableModel>,
        batch_size: usize,
        n_ae: usize,
        n_cls: usize,
        labels: BTreeMap<String, LabelSpec>,
        normal_idx: Option<usize>,
        c2_idx: Option<usize>,
    },
}

impl MLModelAdapter {
    /// Per-attack-type confirmations lookup: resolve the manifest's
    /// `labels[*].confirmations` value whose label name matches
    /// `attack_type_name` (case-insensitive). Callers fall back to their own
    /// default when this returns `None` — `AutoencoderOnly` carries no labels,
    /// and classifier labels may legitimately omit the override.
    pub fn confirmations_for(&self, attack_type_name: &str) -> Option<usize> {
        match self {
            Self::MultiTask { labels, .. } | Self::ClassifierOnly { labels, .. } => {
                confirmations_from_labels(labels, attack_type_name)
            }
            Self::AutoencoderOnly { .. } => None,
        }
    }
}

/// Pure-data lookup extracted so unit tests can cover the matching rules
/// without constructing a full `MLModelAdapter` (which requires a real
/// `RunnableModel` — expensive and fragile to mock).
fn confirmations_from_labels(labels: &BTreeMap<String, LabelSpec>, attack_type_name: &str) -> Option<usize> {
    labels
        .values()
        .find(|spec| spec.name.eq_ignore_ascii_case(attack_type_name))
        .and_then(|spec| spec.confirmations)
}

/// Internal state machine. Held inside `ArcSwap<ModelSourceState>` so the
/// inference pipeline can check state once per tick without locks and
/// atomically swap on upload / deletion / reload failure.
///
/// Variants are deliberately **not** `Serialize` — the `Active` variant
/// holds an `Arc<RunnableModel>` which isn't serde-friendly. Callers that
/// need a wire representation call `to_status()` to produce the lightweight
/// `ModelSourceStatus` consumed by WebSocket / HTTP.
pub enum ModelSourceState {
    /// Day 1 default. `models/` empty, or admin deleted the current model.
    /// Drift detector becomes a no-op; fusion math still runs with the
    /// remaining 3 sources.
    Dormant,
    /// Model loaded, inference ticks consume flows.
    Active { adapter: MLModelAdapter, info: ModelInfo },
    /// Last load attempt failed — schema mismatch, timeout, corrupted
    /// ONNX. Inference skips; UI renders the reason. Swap to Dormant /
    /// Active via normal reload path.
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

    /// Wire-format snapshot for UI / HTTP. Never borrows the adapter — the
    /// returned value is safe to send across WebSocket boundaries.
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
        assert_eq!(confirmations_from_labels(&labels, "Bot"), Some(1));
        assert_eq!(confirmations_from_labels(&labels, "DoS/DDoS"), Some(2));
    }

    #[test]
    fn confirmations_lookup_is_case_insensitive() {
        let labels = sample_labels();
        assert_eq!(confirmations_from_labels(&labels, "bot"), Some(1));
        assert_eq!(confirmations_from_labels(&labels, "dos/ddos"), Some(2));
    }

    #[test]
    fn confirmations_lookup_label_without_override_returns_none() {
        let labels = sample_labels();
        assert_eq!(confirmations_from_labels(&labels, "Normal"), None);
    }

    #[test]
    fn confirmations_lookup_unknown_name_returns_none() {
        let labels = sample_labels();
        assert_eq!(confirmations_from_labels(&labels, "Phantom"), None);
    }

    #[test]
    fn confirmations_lookup_empty_labels_returns_none() {
        let labels = BTreeMap::new();
        assert_eq!(confirmations_from_labels(&labels, "Bot"), None);
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
