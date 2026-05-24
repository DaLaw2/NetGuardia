use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::broadcast;
use tokio::sync::oneshot;

use crate::adapter::flow_trace_store::FsFlowTraceStore;
use crate::adapter::model_loading::artifact_resolver::FsModelArtifactResolver;
use crate::adapter::model_loading::onnx_runtime::OnnxRuntimeLoader;
use crate::common::error::Error;
use crate::common::error::io::IOError;
use crate::core::detection::metrics::FusionMetrics;
use crate::core::inference::alert::MLAlert;
use crate::core::inference::drift_detector::DriftDetectorHandle;
use crate::core::inference::engine::Engine;
use crate::core::inference::engine::EngineConfig;
use crate::core::inference::model_adapter::ModelSourceState;
use crate::core::inference::model_loader::build_adapter;
use crate::core::inference::runner::Inference;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::AuditEvent;
use crate::domain::detection::flow_features::FlowFeatures;
use crate::domain::detection::flow_tracker::FlowLimits;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::domain::detection::model_files::{MANIFEST_FILENAME, MODELS_DIR};
use crate::domain::detection::model_source::ModelInfo;
use crate::infrastructure::flow_trace_logger::{RotationPolicy, TrafficLogger};
use crate::interface::detection::flow_trace_sink::FlowTraceSink;
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;

pub struct InferenceRuntime {
    pub ml_alert: Arc<MLAlert>,
    pub ml_inference: Arc<Inference>,
    pub ml_engine: Arc<Engine>,
    pub fusion_metrics: Arc<FusionMetrics>,
    pub model_runtime_loader: Arc<dyn ModelRuntimeLoader>,
    pub model_artifact_resolver: Arc<dyn ModelArtifactResolver>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl InferenceRuntime {
    pub fn new(
        app_config: Arc<ArcSwap<AppConfig>>,
        inference_config: Arc<MLInferenceConfig>,
        ml_manifest: Option<ModelManifest>,
        drift_detector: DriftDetectorHandle,
        audit_tx: broadcast::Sender<AuditEvent>,
    ) -> Result<Self, Error> {
        let config = app_config.load();
        let batch_size = config.ml.inference.inference_batch_size;
        let onnx_load_timeout = Duration::from_secs(config.ml.inference.onnx_load_timeout_secs);
        let model_runtime_loader: Arc<dyn ModelRuntimeLoader> = Arc::new(OnnxRuntimeLoader);
        let model_artifact_resolver: Arc<dyn ModelArtifactResolver> = Arc::new(FsModelArtifactResolver);

        let initial_state = match ml_manifest.as_ref() {
            Some(manifest) => {
                let manifest_path = PathBuf::from(MODELS_DIR).join(MANIFEST_FILENAME);
                match build_adapter(
                    manifest,
                    Some(&manifest_path),
                    &inference_config,
                    batch_size,
                    onnx_load_timeout,
                    model_runtime_loader.as_ref(),
                    model_artifact_resolver.as_ref(),
                ) {
                    Ok(adapter) => {
                        let info = ModelInfo::new(
                            manifest.name.clone(),
                            manifest.runtime_adapter().to_string(),
                            current_epoch_secs(),
                            manifest.runtime_feature_count(),
                        );
                        log!(MLLog::ModelsLoaded(format!(
                            "{} ({}) — {} features, {} labels",
                            manifest.name,
                            manifest.runtime_adapter(),
                            manifest.runtime_feature_count(),
                            manifest.labels.len()
                        )));
                        ModelSourceState::Active { adapter, info }
                    }
                    Err(e) => {
                        log!(MLLog::ModelReloadFailed(e.to_string()));
                        ModelSourceState::Error {
                            msg: e.to_string(),
                            since: SystemTime::now(),
                            last_attempted_path: Some(manifest_path),
                        }
                    }
                }
            }
            None => {
                log!(MLLog::ModelsLoaded(
                    "no manifest present — ML source dormant".to_string()
                ));
                ModelSourceState::Dormant
            }
        };

        let ml_inference = Arc::new(Inference::new(
            initial_state,
            inference_config.clone(),
            app_config.clone(),
        ));
        let ml_alert = Arc::new(MLAlert::new(config.ml.alert_channel_capacity));

        let traffic_logger = if config.ml.inference.traffic_logging_mode {
            let csv_path = config.ml.inference.traffic_log_csv_path.clone();
            let mut header = FlowFeatures::all_feature_names_owned().to_vec();
            header.push("Label".to_string());
            let base_path = PathBuf::from(&csv_path);
            let policy = RotationPolicy {
                max_file_bytes: config.ml.flow_trace.max_file_bytes,
                max_file_age: Duration::from_secs(config.ml.flow_trace.max_file_age_secs),
                total_budget_bytes: config.ml.flow_trace.total_budget_bytes,
            };
            let logger = TrafficLogger::new(
                &base_path,
                header,
                policy,
                config.ml.flow_trace.traffic_logger_channel_capacity,
                Some(audit_tx.clone()),
                Arc::new(FsFlowTraceStore),
            )
            .map_err(|e| IOError::CreateFileFailed(csv_path.clone(), e))?;
            log!(MLLog::TrafficLoggingEnabled(csv_path));
            Some(Arc::new(logger) as Arc<dyn FlowTraceSink>)
        } else {
            None
        };

        let engine_config = EngineConfig {
            max_flows: config.ml.inference.max_concurrent_flows,
            min_packets: config.ml.inference.min_packets_for_inference,
            min_packets_floor: config.ml.inference.min_packets_floor,
            batch_size: config.ml.inference.inference_batch_size,
            inference_interval_secs: config.ml.inference.inference_interval_secs,
            aggregator_window_secs: config.ml.inference.aggregator_window_secs,
            confirmation_window_fraction: config.ml.inference.confirmation_window_fraction,
        };

        let flow_limits = FlowLimits {
            max_packets_per_direction: config.ml.flow.max_packets_per_direction,
            max_periods: config.ml.flow.max_periods,
            idle_threshold_us: config.ml.flow.idle_threshold_us,
            bulk_min_packets: config.ml.flow.bulk_min_packets,
            bulk_min_bytes: config.ml.flow.bulk_min_bytes,
            idle_timeout_us: config.ml.flow.idle_timeout_us,
            terminated_timeout_us: config.ml.flow.terminated_timeout_us,
        };

        let ml_engine = Arc::new(Engine::new(
            ml_inference.clone(),
            ml_alert.clone(),
            drift_detector,
            engine_config,
            flow_limits,
            traffic_logger,
            config.ebpf.combined_queue_count,
        ));

        let fusion_metrics = Arc::new(FusionMetrics::new());

        Ok(Self {
            ml_alert,
            ml_inference,
            ml_engine,
            fusion_metrics,
            model_runtime_loader,
            model_artifact_resolver,
            shutdowns: SegQueue::new(),
        })
    }

    pub async fn run(&self) -> Result<(), Error> {
        let ml_engine = self.ml_engine.clone();

        let (ml_shutdown, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            ml_engine.run(shutdown_rx).await;
        });
        self.shutdowns.push(ml_shutdown);

        Ok(())
    }

    pub fn terminate(&self) {
        while let Some(shutdown) = self.shutdowns.pop() {
            let _ = shutdown.send(());
        }
    }
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
