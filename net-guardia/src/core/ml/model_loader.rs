use tract_onnx::prelude::*;
use std::path::PathBuf;

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::ml::MLError;
use crate::model::ml_detection::RunnableModel;

use super::config_loader::InferenceConfig;

pub struct MLModels {
    pub deep_autoencoder: RunnableModel,
    pub classifier: RunnableModel,
}
impl MLModels {
    pub fn load_models(app_config: &Arc<AppConfig>, inference_config: &Arc<InferenceConfig>) -> Result<Self, MLError> {
        Ok(Self {
            deep_autoencoder: Self::loader(&app_config.inference.deep_autoencoder_name, inference_config.num_ae_features())?,
            classifier: Self::loader(&app_config.inference.classifier_name, inference_config.num_classifier_features())?
        })
    }

    pub fn loader(model: &str, features: usize) -> Result<RunnableModel, MLError> {
        let model_path = PathBuf::from("models").join(model);

        let load = || -> Result<RunnableModel, Box<dyn std::error::Error>> {
            let mut model = onnx().model_for_path(&model_path)?;
            model.set_input_fact(0, f32::fact(&[1, features]).into())?;
            Ok(model.into_optimized()?.into_runnable()?)
        };

        load().map_err(|_| MLError::ModelLoadFailed(model_path))
    }

    pub fn get_model_info(&self, name: &str) -> String {
        let model = match name {
            "deep_autoencoder" => &self.deep_autoencoder,
            "classifier" => &self.classifier,
            _ => return "unknown model".to_string(),
        };

        let inputs = model.model().inputs.len();
        let outputs = model.model().outputs.len();
        format!("{}: inputs: {}, outputs: {}", name, inputs, outputs)
    }
}