use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;

use crate::adapter::model_loading::artifact_resolver::FsModelArtifactResolver;
use crate::adapter::model_loading::config_loader::FsModelConfigLoader;
use crate::adapter::model_loading::onnx_runtime::OnnxRuntimeLoader;
use crate::adapter::model_promotion_store::FsModelPromotionStore;
use crate::common::error::Error;
use crate::core::common::statistics::FlowStatistics;
use crate::core::inference::drift_detector::{DriftDetectorHandle, DriftDetectorRunner};
use crate::core::inference::inference_runtime::InferenceRuntime;
use crate::core::inference::model_promotion::PromoteGate;
use crate::domain::common::config::AppConfig;
use crate::domain::data_plane::flow_stats::FlowStatsLimits;
use crate::domain::detection::drift::FeatureBaselines;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::infrastructure::model_promotion_deps::ModelPromotionDeps;
use crate::infrastructure::startup::{DetectionRuntime, FoundationRuntime};
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_config_loader::ModelConfigLoader;
use crate::interface::detection::model_promotion_store::ModelPromotionStore;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;

pub fn build_detection(foundation: &FoundationRuntime) -> Result<DetectionRuntime, Error> {
    let (inference_config, ml_manifest) = load_inference_config(&foundation.app_config)?;
    let (drift_detector, drift_detector_runner) = build_drift_detector(&foundation.app_config, &inference_config);
    let inference_runtime = Arc::new(InferenceRuntime::new(
        foundation.app_config.clone(),
        inference_config.clone(),
        ml_manifest,
        drift_detector.clone(),
        foundation.channels.audit_tx.clone(),
    )?);

    let flow_stats_cfg = foundation.app_config.load();
    let flow_stats_limits = FlowStatsLimits::new(
        flow_stats_cfg.detection.flow_stats.max_snapshot_entries,
        flow_stats_cfg.detection.flow_stats.max_top_n,
    );
    drop(flow_stats_cfg);
    let flow_statistics = Arc::new(FlowStatistics::new(
        inference_runtime.ml_engine.clone(),
        flow_stats_limits,
    ));

    let promote_gate = Arc::new(PromoteGate::new());
    let validation_gate = Arc::new(PromoteGate::new());
    let model_promotion_deps = Arc::new(ModelPromotionDeps {
        model_runtime_loader: Arc::new(OnnxRuntimeLoader) as Arc<dyn ModelRuntimeLoader>,
        model_artifact_resolver: Arc::new(FsModelArtifactResolver) as Arc<dyn ModelArtifactResolver>,
        model_config_loader: Arc::new(FsModelConfigLoader) as Arc<dyn ModelConfigLoader>,
        promotion_store: Arc::new(FsModelPromotionStore) as Arc<dyn ModelPromotionStore>,
        validation_gate,
    });

    Ok(DetectionRuntime {
        inference_config,
        inference_runtime,
        flow_statistics,
        drift_detector,
        drift_detector_runner: Some(drift_detector_runner),
        promote_gate,
        model_promotion_deps,
    })
}

fn load_inference_config(
    app_config: &Arc<ArcSwap<AppConfig>>,
) -> Result<(Arc<MLInferenceConfig>, Option<ModelManifest>), Error> {
    let manifest_path = PathBuf::from("models/manifest.yaml");
    let model_config_loader = FsModelConfigLoader;
    if manifest_path.exists() {
        let (cfg, manifest) = model_config_loader.load_manifest_with_sidecar(&manifest_path)?;
        log!(MLLog::ManifestLoaded(
            manifest.name.clone(),
            manifest.runtime_adapter().to_string(),
            manifest.runtime_feature_count(),
            manifest.labels.len(),
        ));
        Ok((Arc::new(cfg), Some(manifest)))
    } else {
        Ok((
            Arc::new(model_config_loader.load_file(&app_config.load().ml.models_config_name)?),
            None,
        ))
    }
}

fn build_drift_detector(
    app_config: &Arc<ArcSwap<AppConfig>>,
    inference_config: &MLInferenceConfig,
) -> (DriftDetectorHandle, DriftDetectorRunner) {
    let baselines = FeatureBaselines::from_inference_config(inference_config);
    let drift_cfg = app_config.load();
    let drift_window_secs = drift_cfg.ml.drift.window_secs;
    let drift_max_snapshots = drift_cfg.ml.drift.max_snapshots;
    let drift_channel_capacity = drift_cfg.ml.drift.channel_capacity;
    drop(drift_cfg);
    DriftDetectorHandle::new(
        baselines,
        Duration::from_secs(drift_window_secs),
        drift_max_snapshots,
        drift_channel_capacity,
    )
}
