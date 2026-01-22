use tract_onnx::prelude::*;
use std::path::Path;
use crate::model::error::ml::MLError;

pub struct MLModels {
    pub deep_autoencoder: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    pub random_forest: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    pub mlp: SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
}

impl MLModels {
    pub fn load_from_dir<P: AsRef<Path>>(models_dir: P) -> Result<Self, MLError> {
        let dir = models_dir.as_ref();

        let da_path = dir.join("deep_autoencoder.onnx");
        let mut da_model = tract_onnx::onnx()
            .model_for_path(&da_path)
            .map_err(|_| {
                MLError::ModelLoadFailed { path: da_path.clone() }
            })?;

        da_model.set_input_fact(0, f32::fact(&[1, 78]).into())
            .map_err(|_| {
                MLError::ModelLoadFailed { path: da_path.clone() }
            })?;

        let deep_autoencoder = da_model
            .into_optimized()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: da_path.clone() }
            })?
            .into_runnable()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: da_path }
            })?;

        let rf_path = dir.join("random_forest.onnx");
        let mut rf_model = tract_onnx::onnx()
            .model_for_path(&rf_path)
            .map_err(|_| {
                MLError::ModelLoadFailed { path: rf_path.clone() }
            })?;

        rf_model.set_input_fact(0, f32::fact(&[1, 78]).into())
            .map_err(|_| {
                MLError::ModelLoadFailed { path: rf_path.clone() }
            })?;

        let random_forest = rf_model
            .into_optimized()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: rf_path.clone() }
            })?
            .into_runnable()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: rf_path }
            })?;

        let mlp_path = dir.join("mlp.onnx");
        let mut mlp_model = tract_onnx::onnx()
            .model_for_path(&mlp_path)
            .map_err(|_| {
                MLError::ModelLoadFailed { path: mlp_path.clone() }
            })?;

        mlp_model.set_input_fact(0, f32::fact(&[1, 78]).into())
            .map_err(|_| {
                MLError::ModelLoadFailed { path: mlp_path.clone() }
            })?;

        let mlp = mlp_model
            .into_optimized()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: mlp_path.clone() }
            })?
            .into_runnable()
            .map_err(|_| {
                MLError::ModelLoadFailed { path: mlp_path }
            })?;

        Ok(Self {
            deep_autoencoder,
            random_forest,
            mlp,
        })
    }
}