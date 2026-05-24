use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "model_upload")]
#[derive(Debug, Clone)]
pub struct ModelUploadConfig {
    #[setting(key = "model_upload_max_onnx_bytes", default = "104857600")]
    pub max_onnx_bytes: usize,
    #[setting(key = "model_upload_max_manifest_bytes", default = "65536")]
    pub max_manifest_bytes: usize,
    #[setting(key = "model_upload_max_scaler_bytes", default = "65536")]
    pub max_scaler_bytes: usize,
}

impl ModelUploadConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_onnx_bytes > 0, "ml.model_upload.max_onnx_bytes")?;
        require_config_field(self.max_manifest_bytes > 0, "ml.model_upload.max_manifest_bytes")?;
        require_config_field(self.max_scaler_bytes > 0, "ml.model_upload.max_scaler_bytes")
    }
}
