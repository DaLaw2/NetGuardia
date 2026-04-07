use std::path::PathBuf;
use std::time::Instant;

use macros::log;
use tract_onnx::prelude::*;

use crate::infrastructure::app_config::AppConfig;
use crate::model::detection::ml_detection::RunnableModel;
use crate::model::error::ml::MLError;
use crate::model::log::ml::MLLog;
use crate::model::system::config::MLInferenceConfig;

pub struct MLModels {
    pub deep_autoencoder: RunnableModel,
    pub classifier: RunnableModel,
    pub batch_size: usize,
}

impl MLModels {
    pub fn load_models(
        app_config: &Arc<AppConfig>,
        inference_config: &Arc<MLInferenceConfig>,
        batch_size: usize,
    ) -> Result<Self, MLError> {
        Ok(Self {
            deep_autoencoder: Self::loader(
                &app_config.inference.deep_autoencoder_name,
                inference_config.num_ae_features(),
                batch_size,
            )?,
            classifier: Self::loader(
                &app_config.inference.classifier_name,
                inference_config.num_classifier_features(),
                batch_size,
            )?,
            batch_size,
        })
    }

    fn loader(model: &str, features: usize, batch_size: usize) -> Result<RunnableModel, MLError> {
        let model_path = PathBuf::from("models").join(model);

        log!(MLLog::ModelLoading(model.to_string(), features, batch_size));

        let start = Instant::now();

        let load = || -> Result<RunnableModel, Box<dyn std::error::Error>> {
            let mut model = onnx().model_for_path(&model_path)?;
            model.set_input_fact(0, f32::fact([batch_size, features]).into())?;
            Ok(model.into_optimized()?.into_runnable()?)
        };

        let result = load().map_err(|_| MLError::ModelLoadFailed(model_path));

        let elapsed_ms = start.elapsed().as_millis() as u64;
        log!(MLLog::ModelLoadComplete(model.to_string(), elapsed_ms));

        result
    }

    pub fn get_model_info(&self, name: &str) -> String {
        let model = match name {
            "deep_autoencoder" => &self.deep_autoencoder,
            "classifier" => &self.classifier,
            _ => return "unknown model".to_string(),
        };

        let inputs = model.model().inputs.len();
        let outputs = model.model().outputs.len();
        format!(
            "{name}: inputs: {inputs}, outputs: {outputs}, batch_size: {}",
            self.batch_size
        )
    }
}
