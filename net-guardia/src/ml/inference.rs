use std::sync::Arc;
use tract_onnx::prelude::*;
use macros::log;

use super::flow_tracker::FlowData;
use super::config_loader::InferenceConfig;
use super::feature_extractor::FlowFeatures;
use super::model_loader::MLModels;

use crate::model::ml_detection::DetectionResult;
use crate::model::log::ml::MLLog;

pub struct Inference {
    pub models: Arc<MLModels>,
    pub config: Arc<InferenceConfig>,
}

impl Inference {
    pub fn new(models: Arc<MLModels>, config: Arc<InferenceConfig>) -> Self {
        Self { models, config }
    }

    pub fn infer_batch(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        flows
            .iter()
            .filter_map(|flow| self.infer_single(flow))
            .collect()
    }

    pub fn infer_single(&self, flow: &FlowData) -> Option<DetectionResult> {
        // extract
        let mut features = FlowFeatures::extract(
            flow,
            &self.config.feature_names
        );

        // pre-process
        features.winsorize(&self.config.clip_params, &self.config.feature_names);
        features.normalize(&self.config.scaler_mean, &self.config.scaler_std);
        features.clip(self.config.post_clip_min, self.config.post_clip_max);

        // input tensor
        let input = tract_ndarray::Array2::from_shape_fn((1, self.config.num_features()), |(_, j)| {
            features.features[j] as f32
        });

        // Deep Autoencoder
        let ae_score = match self.run_autoencoder(&input) {
            Ok(score) => score,
            Err(e) => {
                log!(MLLog::InferenceFailed("DeepAutoEncoder".to_string(), e.to_string()));
                return None;
            }
        };

        // Random Forest
        let rf_score = match self.run_random_forest(&input) {
            Ok(score) => score,
            Err(e) => {
                log!(MLLog::InferenceFailed("RandomForest".to_string(), e.to_string()));
                return None;
            }
        };

        // Ensemble score
        let ensemble_score = self.compute_ensemble_score(ae_score, rf_score);

        let is_anomaly = ensemble_score > self.config.threshold as f32;

        let flow_key = format!(
            "{}:{} -> {}:{} (proto {})",
            flow.flow_key.src_ip,
            flow.flow_key.src_port,
            flow.flow_key.dst_ip,
            flow.flow_key.dst_port,
            flow.flow_key.protocol
        );

        let flow_key_raw = flow.flow_key.clone();

        if is_anomaly {
            // MLP
            let (attack_type, confidence) = match self.run_mlp(&input) {
                Ok((attack_type, conf)) => (attack_type, conf),
                Err(e) => {
                    log!(MLLog::InferenceFailed("MLP".to_string(), e.to_string()));
                    ("UNKNOWN".to_string(), ensemble_score)
                }
            };

            if confidence < 0.75 {
                return Some(DetectionResult {
                    flow_key,
                    flow_key_raw,
                    is_attack: false,
                    attack_type: None,
                    confidence: 1.0 - ensemble_score,
                    ae_score,
                    rf_score,
                    ensemble_score,
                });
            }

            Some(DetectionResult {
                flow_key,
                flow_key_raw,
                is_attack: true,
                attack_type: Some(attack_type),
                confidence,
                ae_score,
                rf_score,
                ensemble_score,
            })
        } else {
            Some(DetectionResult {
                flow_key,
                flow_key_raw,
                is_attack: false,
                attack_type: None,
                confidence: 1.0 - ensemble_score,
                ae_score,
                rf_score,
                ensemble_score,
            })
        }
    }

    fn run_autoencoder(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<f32> {
        let input_tensor = input.clone().into_tensor();

        let result = self
            .models
            .deep_autoencoder
            .run(tvec![input_tensor.into()])?;

        let output = result[0]
            .to_array_view::<f32>()?
            .into_dimensionality::<tract_ndarray::Ix2>()?;

        let diff = input - &output;
        let squared_errors = &diff * &diff;
        let mse = squared_errors.sum() / self.config.num_features() as f32;

        let ae_norm = &self.config.ae_normalization;
        let ae_score = (mse - ae_norm.min as f32) / (ae_norm.max as f32 - ae_norm.min as f32 + 1e-10);
        let ae_score = ae_score.clamp(0.0, 1.0);

        Ok(ae_score)
    }

    fn run_random_forest(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<f32> {
        let input_tensor = input.clone().into_tensor();

        let result = self.models.random_forest.run(tvec![input_tensor.into()])?;

        // output[0] = output_label (i64)
        // output[1] = output_probability (sequence of maps)

        if result.len() > 1 {
            if let Ok(proba) = result[1].to_array_view::<f32>() {
                if proba.len() > 1 {
                    return Ok(proba.iter().nth(1).copied().unwrap_or(0.0));
                } else if proba.len() == 1 {
                    return Ok(proba.iter().next().copied().unwrap_or(0.0));
                }
            }
        }

        let label = result[0].to_array_view::<i64>()?;
        let prediction = label.iter().next().copied().unwrap_or(0);

        Ok(if prediction != 0 { 1.0 } else { 0.0 })
    }

    fn run_mlp(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<(String, f32)> {
        let input_tensor = input.clone().into_tensor();

        let result = self.models.mlp.run(tvec![input_tensor.into()])?;

        let output = result[0].to_array_view::<f32>()?;

        let mut max_prob: f32 = 0.0;
        let mut predicted_class: usize = 0;

        for (i, &prob) in output.iter().enumerate() {
            if prob > max_prob {
                max_prob = prob;
                predicted_class = i;
            }
        }

        let attack_type = self.config
            .attack_labels
            .get(&predicted_class.to_string())
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string());

        Ok((attack_type, max_prob))
    }

    fn compute_ensemble_score(&self, ae_score: f32, rf_score: f32) -> f32 {
        let strategy = &self.config.strategy_name;

        if strategy.starts_with("W_") {
            if let Some(weights_str) = strategy.strip_prefix("W_") {
                let parts: Vec<&str> = weights_str.split(':').collect();
                if parts.len() == 2 {
                    if let (Ok(w1), Ok(w2)) = (parts[0].parse::<f32>(), parts[1].parse::<f32>()) {
                        let w1 = w1 / 10.0;
                        let w2 = w2 / 10.0;
                        return w1 * ae_score + w2 * rf_score;
                    }
                }
            }
            (ae_score + rf_score) / 2.0
        } else {
            match strategy.as_str() {
                "Average" => (ae_score + rf_score) / 2.0,
                "Max" => ae_score.max(rf_score),
                "Min" => ae_score.min(rf_score),
                "Product" => ae_score * rf_score,
                _ => (ae_score + rf_score) / 2.0,
            }
        }
    }
}