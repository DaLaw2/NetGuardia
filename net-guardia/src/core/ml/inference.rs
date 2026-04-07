use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use macros::log;
use tract_onnx::prelude::*;

use super::flow_tracker::FlowData;
use super::model_loader::MLModels;
use crate::model::detection::flow_features::FlowFeatures;
use crate::model::detection::ml_detection::DetectionResult;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

/// (anomaly_scores, per_class_probs, c2_scores)
type ClassifierBatchOutput = (Vec<f32>, Vec<Vec<f32>>, Vec<f32>);

/// Consecutive failures to trip the circuit breaker.
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
/// Window in seconds: failures older than this are forgotten.
const CIRCUIT_BREAKER_WINDOW_SECS: u64 = 60;
/// Cooldown in seconds before re-enabling inference after circuit break.
const CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 120;

pub struct Inference {
    models: ArcSwap<MLModels>,
    pub config: Arc<MLInferenceConfig>,
    c2_class_idx: Option<usize>,
    normal_class_idx: Option<usize>,
    failure_count: AtomicU32,
    failure_window_start: AtomicU64,
    circuit_open_since: AtomicU64,
}

impl Inference {
    pub fn new(models: Arc<MLModels>, config: Arc<MLInferenceConfig>) -> Self {
        let c2_class_idx = Self::find_label_index(&config, "C2 Communication");
        let normal_class_idx = Self::find_label_index(&config, "Normal");
        Self {
            models: ArcSwap::from(models),
            config,
            c2_class_idx,
            normal_class_idx,
            failure_count: AtomicU32::new(0),
            failure_window_start: AtomicU64::new(0),
            circuit_open_since: AtomicU64::new(0),
        }
    }

    /// Atomically swap to new models. Old models are dropped when the last reader finishes.
    pub fn swap_models(&self, new_models: Arc<MLModels>) {
        self.models.store(new_models);
        // Reset circuit breaker on successful model swap
        self.failure_count.store(0, Ordering::Relaxed);
        self.failure_window_start.store(0, Ordering::Relaxed);
        self.circuit_open_since.store(0, Ordering::Relaxed);
    }

    fn find_label_index(config: &MLInferenceConfig, label: &str) -> Option<usize> {
        config
            .attack_labels
            .iter()
            .find(|(_, v)| v.as_str() == label)
            .and_then(|(k, _)| k.parse::<usize>().ok())
    }

    /// Batched inference with circuit breaker protection.
    pub fn infer_batch(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        if self.is_circuit_open() {
            return Vec::new();
        }

        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.infer_batch_inner(flows))) {
            Ok(results) => {
                // Success: reset failure counter
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

    fn infer_batch_inner(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        let models = self.models.load();
        let n = flows.len();
        let batch_size = models.batch_size;
        let n_ae = self.config.num_ae_features();
        let n_cls = self.config.num_classifier_features();

        // Phase 1: preprocess all AE features
        let all_ae_features: Vec<Vec<f32>> = flows.iter().map(|f| self.preprocess_ae_features(f)).collect();

        // Phase 2: run AE in chunks → compute per-flow MSE
        let mut ae_scores = Vec::with_capacity(n);
        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;

            // Build (batch_size, n_ae) tensor, zero-padded
            let ae_input = tract_ndarray::Array2::<f32>::from_shape_fn((batch_size, n_ae), |(i, j)| {
                if i < actual {
                    all_ae_features[chunk_start + i][j]
                } else {
                    0.0
                }
            });

            match Self::run_ae_batch(&models, &ae_input, actual, n_ae) {
                Ok(scores) => ae_scores.extend_from_slice(&scores),
                Err(e) => {
                    log!(MLLog::InferenceFailed("DeepAutoEncoder".to_string(), e.to_string()));
                    self.record_failure();
                    return Vec::new();
                }
            }
        }

        // Phase 3: build classifier input (ae_features ++ ae_score) and run in chunks
        let mut all_anomaly = Vec::with_capacity(n);
        let mut all_class_probs = Vec::with_capacity(n);
        let mut all_c2_scores = Vec::with_capacity(n);

        for chunk_start in (0..n).step_by(batch_size) {
            let chunk_end = (chunk_start + batch_size).min(n);
            let actual = chunk_end - chunk_start;

            // Build (batch_size, n_cls) tensor
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

            match Self::run_classifier_batch(&models, &cls_input, actual) {
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

        // Phase 4: build DetectionResults
        let mut results = Vec::with_capacity(n);
        for i in 0..n {
            let flow = &flows[i];
            let flow_key = format!(
                "{}:{} -> {}:{} (proto {}) [{}]",
                flow.flow_key.src_ip_string(),
                flow.flow_key.src_port,
                flow.flow_key.dst_ip_string(),
                flow.flow_key.dst_port,
                flow.flow_key.protocol,
                flow.direction
            );

            let result = self.build_detection_result(
                flow,
                flow_key,
                ae_scores[i],
                all_anomaly[i],
                &all_class_probs[i],
                all_c2_scores[i],
            );
            results.push(result);
        }

        results
    }

    /// Run AE on a padded batch, return MSE scores for the first `actual` rows.
    fn run_ae_batch(
        models: &MLModels,
        input: &tract_ndarray::Array2<f32>,
        actual: usize,
        n_features: usize,
    ) -> TractResult<Vec<f32>> {
        let result = models.deep_autoencoder.run(tvec![input.clone().into_tensor().into()])?;

        let output = result[0]
            .to_array_view::<f32>()?
            .into_dimensionality::<tract_ndarray::Ix2>()?;

        let diff = input - &output;
        let sq = &diff * &diff;

        let mut scores = Vec::with_capacity(actual);
        let n_f = n_features as f32;
        for i in 0..actual {
            let mse: f32 = sq.row(i).sum() / n_f;
            scores.push(mse);
        }
        Ok(scores)
    }

    /// Returns (anomaly_scores, per_class_probs, c2_scores) for the first `actual` rows.
    fn run_classifier_batch(
        models: &MLModels,
        input: &tract_ndarray::Array2<f32>,
        actual: usize,
    ) -> TractResult<ClassifierBatchOutput> {
        let result = models.classifier.run(tvec![input.clone().into_tensor().into()])?;

        // Output 0: anomaly (batch_size, 1)
        let anomaly_view = result[0].to_array_view::<f32>()?;
        let anomaly: Vec<f32> = (0..actual)
            .map(|i| anomaly_view.as_slice().map(|s| s[i]).unwrap_or(0.0))
            .collect();

        // Output 1: class_probs (batch_size, n_classes)
        let class_view = result[1]
            .to_array_view::<f32>()?
            .into_dimensionality::<tract_ndarray::Ix2>()?;
        let class_probs: Vec<Vec<f32>> = (0..actual)
            .map(|i| class_view.row(i).iter().copied().collect())
            .collect();

        // Output 2: c2_score (batch_size, 1)
        let c2_view = result[2].to_array_view::<f32>()?;
        let c2: Vec<f32> = (0..actual)
            .map(|i| c2_view.as_slice().map(|s| s[i]).unwrap_or(0.0))
            .collect();

        Ok((anomaly, class_probs, c2))
    }

    fn build_detection_result(
        &self,
        flow: &FlowData,
        flow_key: String,
        ae_score: f32,
        anomaly_score: f32,
        class_probs: &[f32],
        c2_score: f32,
    ) -> DetectionResult {
        let is_attack = anomaly_score > self.config.anomaly_threshold;

        let (predicted_class, class_confidence) = class_probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, &p)| (i, p))
            .unwrap_or((0, 0.0));

        let mut attack_type = self
            .config
            .attack_labels
            .get(&predicted_class.to_string())
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let mut confidence = class_confidence;

        // C2 head override
        if c2_score > self.config.c2_threshold {
            let c2_class_prob = self
                .c2_class_idx
                .and_then(|idx| class_probs.get(idx).copied())
                .unwrap_or(0.0);
            if c2_score > c2_class_prob {
                attack_type = "C2 Communication".to_string();
                confidence = c2_score;
            }
        }

        // "Normal" class = benign
        if Some(predicted_class) == self.normal_class_idx && c2_score <= self.config.c2_threshold {
            return DetectionResult {
                flow_key,
                flow_key_raw: flow.flow_key.clone(),
                direction: flow.direction,
                is_attack: false,
                attack_type: None,
                confidence: class_confidence,
                ae_score,
                anomaly_score,
                c2_score,
                packet_count: flow.packet_count() as u64,
                flow_duration_us: flow.duration_us(),
            };
        }

        DetectionResult {
            flow_key,
            flow_key_raw: flow.flow_key.clone(),
            direction: flow.direction,
            is_attack,
            attack_type: if is_attack { Some(attack_type) } else { None },
            confidence,
            ae_score,
            anomaly_score,
            c2_score,
            packet_count: flow.packet_count() as u64,
            flow_duration_us: flow.duration_us(),
        }
    }

    fn preprocess_ae_features(&self, flow: &FlowData) -> Vec<f32> {
        let mut features = FlowFeatures::extract(flow, &self.config.ae_feature_names);
        features.winsorize(&self.config.ae_clip_params, &self.config.ae_feature_names);
        features.normalize(&self.config.ae_scaler_mean, &self.config.ae_scaler_std);
        features.clip(self.config.ae_post_clip_min, self.config.ae_post_clip_max);
        features.features.iter().map(|&x| x as f32).collect()
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
            // Cooldown elapsed — reset and allow inference
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

        // If window has expired, start a new window
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
