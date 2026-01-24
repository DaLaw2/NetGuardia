use std::sync::Arc;
use tract_onnx::prelude::*;
use macros::log;
use crate::model::log::ml::MLLog;
use super::config_loader::InferenceConfig;
use super::feature_extractor::FlowFeatures;
use super::model_loader::MLModels;
use crate::model::ml_detection::{DetectionResult};
use super::flow_tracker::FlowData;

pub struct Inference {
    models: Arc<MLModels>,
    config: Arc<InferenceConfig>,
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
        let mut features = FlowFeatures::extract(flow, self.config.num_features());

        features.normalize(&self.config.scaler_mean, &self.config.scaler_std);

        features.clip(self.config.post_clip_min, self.config.post_clip_max);

        let input = tract_ndarray::Array2::from_shape_fn((1, self.config.num_features()), |(_, j)| {
            features.features[j] as f32
        });

        let ae_error = match self.run_autoencoder(&input) {
            Ok(err) => err,
            Err(e) => {
                log!(MLLog::InferenceFailed { model: "DeepAutoEncoder".to_string(), error: e.to_string() });
                return None;
            }
        };

        let rf_prediction = match self.run_random_forest(&input) {
            Ok(pred) => pred,
            Err(e) => {
                log!(MLLog::InferenceFailed { model: "RandomForest".to_string(), error: e.to_string() });
                return None;
            }
        };

        let mlp_prediction = match self.run_mlp(&input) {
            Ok(pred) => pred,
            Err(e) => {
                log!(MLLog::InferenceFailed { model: "MLP".to_string(), error: e.to_string() });
                return None;
            }
        };

        let is_malicious = self.is_attack(ae_error, rf_prediction, mlp_prediction);

        let attack_type = self.get_attack_label(mlp_prediction);

        let confidence = self.compute_confidence(ae_error, rf_prediction, mlp_prediction);

        let flow_key = format!(
            "{}:{} -> {}:{} (proto {})",
            flow.flow_key.src_ip,
            flow.flow_key.src_port,
            flow.flow_key.dst_ip,
            flow.flow_key.dst_port,
            flow.flow_key.protocol
        );

        Some(DetectionResult {
            flow_key,
            is_malicious,
            attack_type,
            confidence,
            ae_reconstruction_error: ae_error,
            rf_prediction,
            mlp_prediction,
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
        let squared_errors = &diff * &diff;
        let mse = squared_errors.sum() / self.config.num_features() as f32;

        Ok(mse)
    }

    fn run_random_forest(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<usize> {
        let input_tensor = input.clone().into_tensor();

        let result = self.models.random_forest.run(tvec![input_tensor.into()])?;

        let output = result[0].to_array_view::<i64>()?;

        let prediction = output.iter().next().copied().unwrap_or(0) as usize;

        Ok(prediction)
    }

    fn run_mlp(&self, input: &tract_ndarray::Array2<f32>) -> TractResult<usize> {
        let input_tensor = input.clone().into_tensor();

        let result = self.models.mlp.run(tvec![input_tensor.into()])?;

        let output = result[0].to_array_view::<f32>()?;

        let prediction = output
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(idx, _)| idx)
            .unwrap_or(0);

        Ok(prediction)
    }

    fn is_attack(&self, ae_error: f32, rf_pred: usize, mlp_pred: usize) -> bool {
        let ae_anomaly = ae_error > self.config.threshold as f32;

        let rf_attack = rf_pred != 0;
        let mlp_attack = mlp_pred != 0;

        let votes = [ae_anomaly, rf_attack, mlp_attack]
            .iter()
            .filter(|&&x| x)
            .count();

        votes >= 2
    }

    fn get_attack_label(&self, prediction: usize) -> String {
        self.config
            .attack_labels
            .get(&prediction.to_string())
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string())
    }

    fn compute_confidence(&self, ae_error: f32, rf_pred: usize, mlp_pred: usize) -> f32 {
        let ae_conf = if ae_error > self.config.threshold as f32 {
            (ae_error / self.config.threshold as f32).min(1.0)
        } else {
            0.0
        };

        let rf_conf = if rf_pred != 0 { 0.8 } else { 0.2 };
        let mlp_conf = if mlp_pred != 0 { 0.8 } else { 0.2 };

        (ae_conf + rf_conf + mlp_conf) / 3.0
    }
}