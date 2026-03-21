use std::sync::Arc;

use macros::log;
use tract_onnx::prelude::*;

use super::config_loader::InferenceConfig;
use super::feature_extractor::FlowFeatures;
use super::flow_tracker::FlowData;
use super::model_loader::MLModels;
use crate::model::log::ml::MLLog;
use crate::model::ml_detection::DetectionResult;

pub struct Inference {
    pub models: Arc<MLModels>,
    pub config: Arc<InferenceConfig>,
}

impl Inference {
    pub fn new(models: Arc<MLModels>, config: Arc<InferenceConfig>) -> Self {
        Self { models, config }
    }

    pub fn infer_batch(&self, flows: &[FlowData]) -> Vec<DetectionResult> {
        flows.iter().filter_map(|flow| self.infer_single(flow)).collect()
    }

    pub fn infer_single(&self, flow: &FlowData) -> Option<DetectionResult> {
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

        let (attack_type, confidence) = match self.run_classifier(cls_input) {
            Ok(result) => result,
            Err(e) => {
                log!(MLLog::InferenceFailed("LightGBM".to_string(), e.to_string()));
                return None;
            }
        };

        let is_attack = ae_score >= self.config.ae_threshold;

        let flow_key = format!(
            "{}:{} -> {}:{} (proto {}) [{}]",
            flow.flow_key.src_ip_string(),
            flow.flow_key.src_port,
            flow.flow_key.dst_ip_string(),
            flow.flow_key.dst_port,
            flow.flow_key.protocol,
            flow.direction
        );

        Some(DetectionResult {
            flow_key,
            flow_key_raw: flow.flow_key.clone(),
            direction: flow.direction,
            is_attack,
            attack_type: if is_attack { Some(attack_type) } else { None },
            confidence,
            ae_score,
            threshold: self.config.ae_threshold,
        })
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

    /// Classifier 輸入 = 已預處理的 ae_features ++ [ae_anomaly_score]
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
        let result = self
            .models
            .deep_autoencoder
            .run(tvec![input_tensor.into()])?;

        let output = result[0]
            .to_array_view::<f32>()?
            .into_dimensionality::<tract_ndarray::Ix2>()?;

        let diff = input - &output;
        let mse = (&diff * &diff).sum() / self.config.ae_feature_names.len() as f32;

        Ok(mse)
    }

    fn run_classifier(&self, input: tract_ndarray::Array2<f32>) -> TractResult<(String, f32)> {
        let result = self.models.classifier.run(tvec![input.into_tensor().into()])?;

        let output = result[0].to_array_view::<f32>()?;

        let mut max_prob: f32 = 0.0;
        let mut predicted_class: usize = 0;

        for (i, &prob) in output.iter().enumerate() {
            if prob > max_prob {
                max_prob = prob;
                predicted_class = i;
            }
        }

        let attack_type = self
            .config
            .attack_labels
            .get(&predicted_class.to_string())
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string());

        Ok((attack_type, max_prob))
    }
}
