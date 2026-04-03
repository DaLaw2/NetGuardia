use std::sync::Arc;

use macros::log;
use tract_onnx::prelude::*;

use super::flow_tracker::FlowData;
use super::model_loader::MLModels;
use crate::model::detection::flow_features::FlowFeatures;
use crate::model::detection::ml_detection::DetectionResult;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

pub struct Inference {
    pub models: Arc<MLModels>,
    pub config: Arc<MLInferenceConfig>,
}

impl Inference {
    pub fn new(models: Arc<MLModels>, config: Arc<MLInferenceConfig>) -> Self {
        Self { models, config }
    }

    pub fn infer_batch(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        flows.iter().filter_map(|flow| self.infer_single(flow)).collect()
    }

    pub fn infer_single(&self, flow: &FlowData) -> Option<DetectionResult> {
        // catch_unwind protects against tract-onnx internal panics on edge-case inputs.
        // Without this, panic=abort config would kill the entire process.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.infer_single_inner(flow))) {
            Ok(result) => result,
            Err(_) => {
                log!(MLLog::InferenceFailed(
                    "ONNX".to_string(),
                    "inference panicked (caught)".to_string(),
                ));
                None
            }
        }
    }

    fn infer_single_inner(&self, flow: &FlowData) -> Option<DetectionResult> {
        let ae_features = self.preprocess_ae_features(flow);

        let ae_input = Self::vec_to_array2(&ae_features);
        let ae_score = match self.run_autoencoder(&ae_input) {
            Ok(score) => score,
            Err(e) => {
                log!(MLLog::InferenceFailed("DeepAutoEncoder".to_string(), e.to_string()));
                return None;
            }
        };

        let cls_input = self.build_classifier_input(&ae_features, ae_score);

        let flow_key = format!(
            "{}:{} -> {}:{} (proto {}) [{}]",
            flow.flow_key.src_ip_string(),
            flow.flow_key.src_port,
            flow.flow_key.dst_ip_string(),
            flow.flow_key.dst_port,
            flow.flow_key.protocol,
            flow.direction
        );

        let result = match self.models.classifier.run(tvec![cls_input.into_tensor().into()]) {
            Ok(r) => r,
            Err(e) => {
                log!(MLLog::InferenceFailed("MultiTaskModel".to_string(), e.to_string()));
                return None;
            }
        };

        // Output 0: anomaly (shape [1,1], sigmoid)
        let anomaly_score = match result[0].to_array_view::<f32>() {
            Ok(v) => *v.iter().next().unwrap_or(&0.0),
            Err(e) => {
                log!(MLLog::InferenceFailed("anomaly_head".to_string(), e.to_string()));
                return None;
            }
        };

        // Output 1: class_probs (shape [1, n_classes], softmax)
        let class_probs = match result[1].to_array_view::<f32>() {
            Ok(v) => v.iter().copied().collect::<Vec<f32>>(),
            Err(e) => {
                log!(MLLog::InferenceFailed("class_head".to_string(), e.to_string()));
                return None;
            }
        };

        // Output 2: c2_score (shape [1,1], sigmoid)
        let c2_score = match result[2].to_array_view::<f32>() {
            Ok(v) => *v.iter().next().unwrap_or(&0.0),
            Err(e) => {
                log!(MLLog::InferenceFailed("c2_head".to_string(), e.to_string()));
                return None;
            }
        };

        let is_attack = anomaly_score > self.config.anomaly_threshold;

        // Determine attack type from class_head argmax
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

        // C2 head override: if C2 head fires and its confidence exceeds the class head's
        // C2 probability, prefer the dedicated C2 head judgment.
        if c2_score > self.config.c2_threshold {
            let c2_class_prob = self.find_class_prob_for("C2 Communication", &class_probs);
            if c2_score > c2_class_prob {
                attack_type = "C2 Communication".to_string();
                confidence = c2_score;
            }
        }

        // "Normal" class prediction means benign
        if attack_type == "Normal" {
            return Some(DetectionResult {
                flow_key,
                flow_key_raw: flow.flow_key.clone(),
                direction: flow.direction,
                is_attack: false,
                attack_type: None,
                confidence: class_confidence,
                ae_score,
                threshold: self.config.anomaly_threshold,
                packet_count: flow.packet_count() as u64,
                flow_duration_us: flow.duration_us(),
            });
        }

        Some(DetectionResult {
            flow_key,
            flow_key_raw: flow.flow_key.clone(),
            direction: flow.direction,
            is_attack,
            attack_type: if is_attack { Some(attack_type) } else { None },
            confidence,
            ae_score,
            threshold: self.config.anomaly_threshold,
            packet_count: flow.packet_count() as u64,
            flow_duration_us: flow.duration_us(),
        })
    }

    /// Find the softmax probability for a given label name in class_probs.
    fn find_class_prob_for(&self, label: &str, class_probs: &[f32]) -> f32 {
        for (key, name) in &self.config.attack_labels {
            if name == label && let Ok(idx) = key.parse::<usize>() {
                return class_probs.get(idx).copied().unwrap_or(0.0);
            }
        }
        0.0
    }

    fn preprocess_ae_features(&self, flow: &FlowData) -> Vec<f32> {
        let mut features = FlowFeatures::extract(flow, &self.config.ae_feature_names);
        features.winsorize(&self.config.ae_clip_params, &self.config.ae_feature_names);
        features.normalize(&self.config.ae_scaler_mean, &self.config.ae_scaler_std);
        features.clip(self.config.ae_post_clip_min, self.config.ae_post_clip_max);
        features.features.iter().map(|&x| x as f32).collect()
    }

    fn vec_to_array2(v: &[f32]) -> tract_ndarray::Array2<f32> {
        tract_ndarray::Array2::from_shape_fn((1, v.len()), |(_, j)| v[j])
    }

    /// Classifier input = preprocessed ae_features ++ [ae_anomaly_score]
    fn build_classifier_input(&self, ae_features: &[f32], ae_score: f32) -> tract_ndarray::Array2<f32> {
        let n = ae_features.len() + 1;
        tract_ndarray::Array2::from_shape_fn((1, n), |(_, j)| {
            if j < ae_features.len() {
                ae_features[j]
            } else {
                ae_score
            }
        })
    }

    fn run_autoencoder(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<f32> {
        let input_tensor = input.clone().into_tensor();
        let result = self.models.deep_autoencoder.run(tvec![input_tensor.into()])?;

        let output = result[0]
            .to_array_view::<f32>()?
            .into_dimensionality::<tract_ndarray::Ix2>()?;

        let diff = input - &output;
        let mse = (&diff * &diff).sum() / self.config.ae_feature_names.len() as f32;

        Ok(mse)
    }
}
