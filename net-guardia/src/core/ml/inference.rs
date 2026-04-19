//! Inference pipeline — state-aware, adapter-dispatched.
//!
//! The pipeline holds `ArcSwap<ModelSourceState>` so the engine can take a
//! lock-free snapshot per tick and `infer_batch` dispatches on whichever
//! `MLModelAdapter` variant the active state carries.
//!
//! The MultiTask arm fires on any of: anomaly head above threshold,
//! classifier picking a non-Normal class at ≥ `class_min_confidence`, or the
//! C2 head elevated above its own threshold — so AE reconstruction error
//! can't mask a stealthy attack the classifier does recognize.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use macros::log;
use tract_onnx::prelude::*;

use super::adapter::{MLModelAdapter, ModelSourceState};
use super::flow_tracker::FlowData;
use super::manifest::LabelSpec;
use crate::model::detection::flow_features::FlowFeatures;
use crate::model::detection::ml_detection::{DetectionResult, RunnableModel};
use crate::model::detection::model_source::ModelSourceStatus;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

/// (anomaly_scores, per_class_probs, c2_scores) — MultiTask batch output.
type ClassifierBatchOutput = (Vec<f32>, Vec<Vec<f32>>, Vec<f32>);

/// Consecutive failures to trip the circuit breaker.
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
/// Window in seconds: failures older than this are forgotten.
const CIRCUIT_BREAKER_WINDOW_SECS: u64 = 60;
/// Cooldown in seconds before re-enabling inference after circuit break.
const CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 120;

pub struct Inference {
    state: ArcSwap<ModelSourceState>,
    pub config: Arc<MLInferenceConfig>,
    /// Rolling-window QPS estimate, published in `ModelInfo.qps_recent`.
    /// Stored as u32 (integer QPS) for lock-free update; fractional QPS
    /// information is not useful at the UI grain we're publishing.
    qps_recent: AtomicU32,
    failure_count: AtomicU32,
    failure_window_start: AtomicU64,
    circuit_open_since: AtomicU64,
}

impl Inference {
    /// Build a new Inference with the given initial state. Use
    /// `ModelSourceState::Dormant` when no model is loaded (Day 1 default).
    pub fn new(initial_state: ModelSourceState, config: Arc<MLInferenceConfig>) -> Self {
        Self {
            state: ArcSwap::from_pointee(initial_state),
            config,
            qps_recent: AtomicU32::new(0),
            failure_count: AtomicU32::new(0),
            failure_window_start: AtomicU64::new(0),
            circuit_open_since: AtomicU64::new(0),
        }
    }

    /// Atomically swap in a new state. Any transition INTO `Active` resets
    /// the circuit breaker so a freshly loaded model starts with a clean
    /// failure record; `Error ↔ Dormant` transitions leave the CB alone.
    pub fn swap_state(&self, new_state: ModelSourceState) {
        let new_is_active = new_state.is_active();
        self.state.store(Arc::new(new_state));
        if new_is_active {
            self.failure_count.store(0, Ordering::Relaxed);
            self.failure_window_start.store(0, Ordering::Relaxed);
            self.circuit_open_since.store(0, Ordering::Relaxed);
        }
    }

    /// Current state snapshot for wire broadcast. Merges the in-memory
    /// `qps_recent` atomic into the Active info so the UI sees live QPS.
    pub fn current_status(&self) -> ModelSourceStatus {
        let guard = self.state.load();
        let mut status = guard.to_status();
        if let ModelSourceStatus::Active { ref mut info } = status {
            info.qps_recent = self.qps_recent.load(Ordering::Relaxed) as f32;
        }
        status
    }

    pub fn is_active(&self) -> bool {
        self.state.load().is_active()
    }

    /// Per-attack-type confirmations from the active manifest's labels.
    /// Returns `None` when the source is Dormant/Error or when the label has
    /// no `confirmations` override; callers apply their own fallback.
    pub fn confirmations_for_attack_type(&self, attack_type_name: &str) -> Option<usize> {
        match self.state.load().as_ref() {
            ModelSourceState::Active { adapter, .. } => adapter.confirmations_for(attack_type_name),
            ModelSourceState::Dormant | ModelSourceState::Error { .. } => None,
        }
    }

    /// Batched inference with circuit breaker protection + state dispatch.
    /// Returns an empty Vec when Dormant / Error / circuit-open.
    pub fn infer_batch(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        if self.is_circuit_open() {
            return Vec::new();
        }

        // Snapshot the state once so the whole batch sees a consistent adapter.
        let guard = self.state.load();
        let adapter = match guard.as_ref() {
            ModelSourceState::Active { adapter, .. } => adapter,
            ModelSourceState::Dormant | ModelSourceState::Error { .. } => {
                return Vec::new();
            }
        };

        match panic::catch_unwind(AssertUnwindSafe(|| self.infer_batch_inner(adapter, flows))) {
            Ok(results) => {
                self.failure_count.store(0, Ordering::Relaxed);
                self.failure_window_start.store(0, Ordering::Relaxed);
                results
            }
            Err(_) => {
                log!(MLLog::InferenceFailed(
                    "ONNX".to_string(),
                    "batch inference panicked (caught)".to_string(),
                ));
                self.record_failure();
                Vec::new()
            }
        }
    }

    /// Dispatch on adapter variant.
    fn infer_batch_inner(&self, adapter: &MLModelAdapter, flows: &[FlowData]) -> Vec<DetectionResult> {
        match adapter {
            MLModelAdapter::MultiTask {
                ae,
                classifier,
                batch_size,
                n_ae,
                n_cls,
                labels,
                normal_idx,
                c2_idx,
            } => self.infer_multitask(
                ae,
                classifier,
                *batch_size,
                *n_ae,
                *n_cls,
                labels,
                *normal_idx,
                *c2_idx,
                flows,
            ),
            MLModelAdapter::AutoencoderOnly {
                model,
                batch_size,
                n_features,
            } => self.infer_autoencoder_only(model, *batch_size, *n_features, flows),
            MLModelAdapter::ClassifierOnly {
                model,
                batch_size,
                n_features,
                labels,
                normal_idx,
            } => self.infer_classifier_only(model, *batch_size, *n_features, labels, *normal_idx, flows),
        }
    }

    /// MultiTask path. Runs the AE batch → computes per-flow MSE → feeds the
    /// classifier over (ae_features ++ ae_score) → fires on anomaly OR
    /// non-Normal classifier agreement OR elevated C2 head.
    #[allow(clippy::too_many_arguments)]
    fn infer_multitask(
        &self,
        ae: &RunnableModel,
        classifier: &RunnableModel,
        batch_size: usize,
        n_ae: usize,
        n_cls: usize,
        labels: &BTreeMap<String, LabelSpec>,
        normal_idx: Option<usize>,
        c2_idx: Option<usize>,
        flows: &[FlowData],
    ) -> Vec<DetectionResult> {
        let n = flows.len();

        let all_ae_features: Vec<Vec<f32>> = flows.iter().map(|f| self.preprocess_ae_features(f)).collect();

        let mut ae_scores = Vec::with_capacity(n);
        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;
            let ae_input = tract_ndarray::Array2::<f32>::from_shape_fn((batch_size, n_ae), |(i, j)| {
                if i < actual {
                    all_ae_features[chunk_start + i][j]
                } else {
                    0.0
                }
            });

            match run_ae_batch(ae, &ae_input, actual, n_ae) {
                Ok(scores) => ae_scores.extend_from_slice(&scores),
                Err(e) => {
                    log!(MLLog::InferenceFailed("DeepAutoEncoder".to_string(), e.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            }
        }

        let mut all_anomaly = Vec::with_capacity(n);
        let mut all_class_probs = Vec::with_capacity(n);
        let mut all_c2_scores = Vec::with_capacity(n);

        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;

            let cls_input = tract_ndarray::Array2::<f32>::from_shape_fn((batch_size, n_cls), |(i, j)| {
                if i < actual {
                    if j < n_ae {
                        all_ae_features[chunk_start + i][j]
                    } else {
                        ae_scores[chunk_start + i]
                    }
                } else {
                    0.0
                }
            });

            match run_classifier_batch(classifier, &cls_input, actual) {
                Ok((anomaly, class_probs, c2)) => {
                    all_anomaly.extend_from_slice(&anomaly);
                    all_class_probs.extend(class_probs);
                    all_c2_scores.extend_from_slice(&c2);
                }
                Err(e) => {
                    log!(MLLog::InferenceFailed("MultiTaskModel".to_string(), e.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            }
        }

        let mut results = Vec::with_capacity(n);
        let class_min_conf = self.config.class_min_confidence;
        let anomaly_thr = self.config.anomaly_threshold;
        let c2_thr = self.config.c2_threshold;

        for i in 0..n {
            let flow = &flows[i];
            let class_probs = &all_class_probs[i];
            let anomaly = all_anomaly[i];
            let c2 = all_c2_scores[i];

            let (predicted_class, class_confidence) = argmax(class_probs);
            let attack_type_name = labels
                .get(&predicted_class.to_string())
                .map(|l| l.name.clone())
                .unwrap_or_else(|| "UNKNOWN".to_string());

            let classifier_fires =
                normal_idx.is_none_or(|ni| predicted_class != ni) && class_confidence >= class_min_conf;
            let c2_fires = c2 > c2_thr;
            let mut is_attack = anomaly > anomaly_thr || classifier_fires || c2_fires;

            // "Normal" with no C2 elevation stays benign regardless of AE noise.
            if normal_idx == Some(predicted_class) && !c2_fires {
                is_attack = false;
            }

            // When the manifest declares a C2 class and its head score beats
            // the classifier's probability for that same class, relabel the
            // event with the manifest's C2 label and use the head score as
            // the outgoing confidence. Manifests without a C2 class keep the
            // argmax label and class-confidence untouched.
            let mut attack_type = attack_type_name;
            let mut confidence = class_confidence;
            if c2_fires
                && let Some(idx) = c2_idx
                && let Some(c2_class_prob) = class_probs.get(idx).copied()
                && c2 > c2_class_prob
            {
                if let Some(spec) = labels.get(&idx.to_string()) {
                    attack_type = spec.name.clone();
                }
                confidence = c2;
            }

            results.push(DetectionResult {
                flow_key: build_flow_key_label(flow),
                flow_key_raw: flow.flow_key.clone(),
                direction: flow.direction,
                is_attack,
                attack_type: if is_attack { Some(attack_type) } else { None },
                confidence,
                ae_score: ae_scores[i],
                anomaly_score: anomaly,
                c2_score: c2,
                packet_count: flow.packet_count() as u64,
                flow_duration_us: flow.duration_us(),
            });
        }

        results
    }

    /// AutoencoderOnly path. Output is reconstruction MSE; when it exceeds
    /// `anomaly_threshold` the flow is marked as a generic `anomaly`. There
    /// are no classifier outputs, so no per-class gating happens here.
    fn infer_autoencoder_only(
        &self,
        model: &RunnableModel,
        batch_size: usize,
        n_features: usize,
        flows: &[FlowData],
    ) -> Vec<DetectionResult> {
        let n = flows.len();
        let all_features: Vec<Vec<f32>> = flows.iter().map(|f| self.preprocess_ae_features(f)).collect();
        let mut scores = Vec::with_capacity(n);

        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;
            let input = tract_ndarray::Array2::<f32>::from_shape_fn((batch_size, n_features), |(i, j)| {
                if i < actual {
                    all_features[chunk_start + i][j]
                } else {
                    0.0
                }
            });
            match run_ae_batch(model, &input, actual, n_features) {
                Ok(s) => scores.extend_from_slice(&s),
                Err(e) => {
                    log!(MLLog::InferenceFailed("AutoencoderOnly".to_string(), e.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            }
        }

        let thr = self.config.anomaly_threshold;
        flows
            .iter()
            .zip(scores.iter())
            .map(|(flow, &score)| {
                let is_attack = score > thr;
                DetectionResult {
                    flow_key: build_flow_key_label(flow),
                    flow_key_raw: flow.flow_key.clone(),
                    direction: flow.direction,
                    is_attack,
                    attack_type: if is_attack { Some("anomaly".to_string()) } else { None },
                    // AE-only has no separate classifier confidence; reuse the score.
                    confidence: score,
                    ae_score: score,
                    anomaly_score: score,
                    c2_score: 0.0,
                    packet_count: flow.packet_count() as u64,
                    flow_duration_us: flow.duration_us(),
                }
            })
            .collect()
    }

    /// ClassifierOnly path. Output is per-class softmax; the manifest's
    /// labels drive attack_type and the flow fires when the argmax class
    /// isn't Normal and confidence ≥ `class_min_confidence`.
    fn infer_classifier_only(
        &self,
        model: &RunnableModel,
        batch_size: usize,
        n_features: usize,
        labels: &BTreeMap<String, LabelSpec>,
        normal_idx: Option<usize>,
        flows: &[FlowData],
    ) -> Vec<DetectionResult> {
        let n = flows.len();
        let all_features: Vec<Vec<f32>> = flows.iter().map(|f| self.preprocess_ae_features(f)).collect();
        let class_min_conf = self.config.class_min_confidence;
        let mut results = Vec::with_capacity(n);

        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;
            let input = tract_ndarray::Array2::<f32>::from_shape_fn((batch_size, n_features), |(i, j)| {
                if i < actual {
                    all_features[chunk_start + i][j]
                } else {
                    0.0
                }
            });
            let class_probs = match run_classifier_only_batch(model, &input, actual) {
                Ok(cp) => cp,
                Err(e) => {
                    log!(MLLog::InferenceFailed("ClassifierOnly".to_string(), e.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            };

            for (i, probs) in class_probs.into_iter().enumerate() {
                let flow = &flows[chunk_start + i];
                let (predicted_class, confidence) = argmax(&probs);
                let is_attack = normal_idx.is_none_or(|ni| predicted_class != ni) && confidence >= class_min_conf;
                let attack_type = if is_attack {
                    labels
                        .get(&predicted_class.to_string())
                        .map(|l| l.name.clone())
                        .unwrap_or_else(|| "UNKNOWN".to_string())
                } else {
                    "Normal".to_string()
                };
                results.push(DetectionResult {
                    flow_key: build_flow_key_label(flow),
                    flow_key_raw: flow.flow_key.clone(),
                    direction: flow.direction,
                    is_attack,
                    attack_type: if is_attack { Some(attack_type) } else { None },
                    confidence,
                    ae_score: 0.0,
                    anomaly_score: 0.0,
                    c2_score: 0.0,
                    packet_count: flow.packet_count() as u64,
                    flow_duration_us: flow.duration_us(),
                });
            }
        }

        results
    }

    fn preprocess_ae_features(&self, flow: &FlowData) -> Vec<f32> {
        let mut features = FlowFeatures::extract(flow, &self.config.ae_feature_names);
        features.winsorize(&self.config.ae_clip_params, &self.config.ae_feature_names);
        features.normalize(&self.config.ae_scaler_mean, &self.config.ae_scaler_std);
        features.clip(self.config.ae_post_clip_min, self.config.ae_post_clip_max);
        features.features.iter().map(|&x| x as f32).collect()
    }

    /// Publish a rolling QPS estimate visible in `current_status().info.qps_recent`.
    /// Called by the engine after each inference tick completes.
    pub fn record_tick_qps(&self, flows_per_second: f32) {
        self.qps_recent
            .store(flows_per_second.max(0.0) as u32, Ordering::Relaxed);
    }

    // -- Circuit breaker ---------------------------------------------------------

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn is_circuit_open(&self) -> bool {
        let open_since = self.circuit_open_since.load(Ordering::Relaxed);
        if open_since == 0 {
            return false;
        }
        let elapsed = Self::now_secs().saturating_sub(open_since);
        if elapsed >= CIRCUIT_BREAKER_COOLDOWN_SECS {
            self.circuit_open_since.store(0, Ordering::Relaxed);
            self.failure_count.store(0, Ordering::Relaxed);
            self.failure_window_start.store(0, Ordering::Relaxed);
            log!(MLLog::CircuitBreakerReset(CIRCUIT_BREAKER_COOLDOWN_SECS));
            return false;
        }
        true
    }

    fn record_failure(&self) {
        let now = Self::now_secs();
        let window_start = self.failure_window_start.load(Ordering::Relaxed);

        if window_start == 0 || now.saturating_sub(window_start) > CIRCUIT_BREAKER_WINDOW_SECS {
            self.failure_window_start.store(now, Ordering::Relaxed);
            self.failure_count.store(1, Ordering::Relaxed);
            return;
        }

        let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count >= CIRCUIT_BREAKER_THRESHOLD {
            self.circuit_open_since.store(now, Ordering::Relaxed);
            log!(MLLog::CircuitBreakerOpen(count, CIRCUIT_BREAKER_WINDOW_SECS));
        }
    }
}

// -- Free helpers (can be unit-tested without an Inference) -------------------

fn argmax(probs: &[f32]) -> (usize, f32) {
    probs
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(CmpOrdering::Equal))
        .map(|(i, &p)| (i, p))
        .unwrap_or((0, 0.0))
}

fn build_flow_key_label(flow: &FlowData) -> String {
    format!(
        "{}:{} -> {}:{} (proto {}) [{}]",
        flow.flow_key.src_ip_string(),
        flow.flow_key.src_port,
        flow.flow_key.dst_ip_string(),
        flow.flow_key.dst_port,
        flow.flow_key.protocol,
        flow.direction
    )
}

/// Run an autoencoder-style model: output shape == input shape, score is
/// per-row mean squared error between input and reconstruction.
fn run_ae_batch(
    model: &RunnableModel,
    input: &tract_ndarray::Array2<f32>,
    actual: usize,
    n_features: usize,
) -> TractResult<Vec<f32>> {
    let result = model.run(tvec![input.clone().into_tensor().into()])?;
    let output = result[0]
        .to_array_view::<f32>()?
        .into_dimensionality::<tract_ndarray::Ix2>()?;
    let diff = input - &output;
    let sq = &diff * &diff;

    let mut scores = Vec::with_capacity(actual);
    let n_f = n_features as f32;
    for i in 0..actual {
        scores.push(sq.row(i).sum() / n_f);
    }
    Ok(scores)
}

/// Run a 3-output multi-task classifier: (anomaly, class_probs, c2_score).
fn run_classifier_batch(
    model: &RunnableModel,
    input: &tract_ndarray::Array2<f32>,
    actual: usize,
) -> TractResult<ClassifierBatchOutput> {
    let result = model.run(tvec![input.clone().into_tensor().into()])?;

    let anomaly_view = result[0].to_array_view::<f32>()?;
    let anomaly: Vec<f32> = (0..actual)
        .map(|i| anomaly_view.as_slice().map(|s| s[i]).unwrap_or(0.0))
        .collect();

    let class_view = result[1]
        .to_array_view::<f32>()?
        .into_dimensionality::<tract_ndarray::Ix2>()?;
    let class_probs: Vec<Vec<f32>> = (0..actual)
        .map(|i| class_view.row(i).iter().copied().collect())
        .collect();

    let c2_view = result[2].to_array_view::<f32>()?;
    let c2: Vec<f32> = (0..actual)
        .map(|i| c2_view.as_slice().map(|s| s[i]).unwrap_or(0.0))
        .collect();

    Ok((anomaly, class_probs, c2))
}

/// Run a single-output classifier (ClassifierOnly adapter).
fn run_classifier_only_batch(
    model: &RunnableModel,
    input: &tract_ndarray::Array2<f32>,
    actual: usize,
) -> TractResult<Vec<Vec<f32>>> {
    let result = model.run(tvec![input.clone().into_tensor().into()])?;
    let view = result[0]
        .to_array_view::<f32>()?
        .into_dimensionality::<tract_ndarray::Ix2>()?;
    Ok((0..actual).map(|i| view.row(i).iter().copied().collect()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argmax_picks_highest() {
        let (idx, val) = argmax(&[0.1, 0.5, 0.3, 0.4]);
        assert_eq!(idx, 1);
        assert!((val - 0.5).abs() < 1e-6);
    }

    #[test]
    fn argmax_empty_returns_zero() {
        assert_eq!(argmax(&[]), (0, 0.0));
    }

    #[test]
    fn argmax_equal_picks_last() {
        // Iterator::max_by returns the LAST element when comparisons are
        // equal (in contrast to min_by). Ties in softmax probabilities are
        // rare in practice, and "last wins" is a consistent contract across
        // this codebase.
        let (idx, _) = argmax(&[0.25, 0.25, 0.25, 0.25]);
        assert_eq!(idx, 3);
    }
}
