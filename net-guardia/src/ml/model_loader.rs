use tract_onnx::prelude::*;
use std::path::PathBuf;

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::ml::MLError;
use crate::model::ml_detection::RunnableModel;

pub struct MLModels {
    pub deep_autoencoder: RunnableModel,
    pub random_forest: RunnableModel,
    pub mlp: RunnableModel,
}
impl MLModels {
    pub fn load_models(app_config: &Arc<AppConfig>, features: usize) -> Result<Self, MLError> {
        Ok(Self {
            deep_autoencoder: Self::loader(&app_config.deep_autoencoder_name, features)?,
            random_forest: Self::loader(&app_config.random_forest_name, features)?,
            mlp: Self::loader(&app_config.mlp_name, features)?,
        })
    }

    pub fn loader(model: &str, features: usize) -> Result<RunnableModel, MLError> {
        let model_path = PathBuf::from("models").join(model);

        let mut model = onnx()
            .model_for_path(&model_path)
            .map_err(|_| {
                MLError::ModelLoadFailed { path: model_path.clone() }
            })?;

        model.set_input_fact(0, f32::fact(&[1, features]).into())
            .map_err(|_| {
                MLError::ModelLoadFailed { path: model_path.clone() }
            })?;

        let runnable_model = model
            .into_optimized()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: model_path.clone() }
            })?
            .into_runnable()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: model_path }
            })?;

        Ok(runnable_model)
    }

    pub fn get_model_info(&self, name: &str) -> String {
        let model = match name {
            "deep_autoencoder" => &self.deep_autoencoder,
            "random_forest" => &self.random_forest,
            "mlp" => &self.mlp,
            _ => return "unknown model".to_string(),
        };

        let inputs = model.model().inputs.len();
        let outputs = model.model().outputs.len();
        format!("{}: inputs: {}, outputs: {}", name, inputs, outputs)
    }
}