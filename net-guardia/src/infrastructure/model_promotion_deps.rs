use std::sync::Arc;

use crate::core::inference::model_promotion::PromoteGate;
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_config_loader::ModelConfigLoader;
use crate::interface::detection::model_promotion_store::ModelPromotionStore;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;

pub struct ModelPromotionDeps {
    pub model_runtime_loader: Arc<dyn ModelRuntimeLoader>,
    pub model_artifact_resolver: Arc<dyn ModelArtifactResolver>,
    pub model_config_loader: Arc<dyn ModelConfigLoader>,
    pub promotion_store: Arc<dyn ModelPromotionStore>,
    pub validation_gate: Arc<PromoteGate>,
}
