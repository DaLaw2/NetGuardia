use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::core::inference::alert::MLAlert;
use crate::core::inference::drift_detector::DriftDetectorHandle;
use crate::core::inference::engine::Engine;
use crate::core::inference::inference::Inference;
use crate::core::inference::model_loader::build_adapter;
use crate::core::inference::traffic_logger::{RotationPolicy, TrafficLogger};
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{MANIFEST_FILENAME, MODELS_DIR};
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::domain::common::error::system::SystemError;
use crate::domain::common::log::system::SystemLog;
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::detection::flow_features::FlowFeatures;
use crate::domain::detection::flow_tracker::FlowLimits;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::ModelManifest;
use crate::domain::detection::metrics::FusionMetrics;
use crate::domain::detection::ml_detection::EngineConfig;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::domain::detection::model_adapter::ModelSourceState;
use crate::domain::detection::model_source::ModelInfo;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::statistics::FlowStatistics;

/// Application-level service orchestrator.
/// Holds all runtime services (health monitoring, ML inference, flow statistics)
/// and manages their lifecycle (start/shutdown).
pub struct AppServices {
    pub health: Arc<SystemHealth>,
    pub ml_alert: Arc<MLAlert>,
    pub ml_inference: Arc<Inference>,
    pub ml_engine: Arc<Engine>,
    pub flow_statistics: Arc<FlowStatistics>,
    pub fusion_metrics: Arc<FusionMetrics>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl AppServices {
    pub fn new(
        app_config: Arc<ArcSwap<AppConfig>>,
        inference_config: Arc<MLInferenceConfig>,
        ml_manifest: Option<ModelManifest>,
        drift_detector: DriftDetectorHandle,
        ebpf_health: Arc<ArcSwap<EbpfHealth>>,
        comm: Arc<CommunicationManager>,
    ) -> Result<Self, Error> {
        let health = SystemHealth::new(app_config.clone(), ebpf_health)?;

        let config = app_config.load();
        let batch_size = config.ml.inference_batch_size;
        let onnx_load_timeout = Duration::from_secs(config.ml.onnx_load_timeout_secs);

        let initial_state = match ml_manifest.as_ref() {
            Some(manifest) => {
                let manifest_path = PathBuf::from(MODELS_DIR).join(MANIFEST_FILENAME);
                match build_adapter(
                    manifest,
                    Some(&manifest_path),
                    &inference_config,
                    batch_size,
                    onnx_load_timeout,
                ) {
                    Ok(adapter) => {
                        let info = ModelInfo::new(
                            manifest.name.clone(),
                            manifest.adapter.as_str().to_string(),
                            manifest.features.len(),
                        );
                        log!(MLLog::ModelsLoaded(format!(
                            "{} ({}) — {} features, {} labels",
                            manifest.name,
                            manifest.adapter.as_str(),
                            manifest.features.len(),
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

        let traffic_logger = if config.ml.traffic_logging_mode {
            let csv_path = config.ml.traffic_log_csv_path.clone();
            let mut header = FlowFeatures::all_feature_names_owned();
            header.push("Label".to_string());
            let base_path = PathBuf::from(&csv_path);
            let policy = RotationPolicy {
                max_file_bytes: config.ml.flow_trace_max_file_bytes,
                max_file_age: Duration::from_secs(config.ml.flow_trace_max_file_age_secs),
                total_budget_bytes: config.ml.flow_trace_total_budget_bytes,
            };
            let logger = TrafficLogger::new(
                &base_path,
                header,
                policy,
                config.ml.traffic_logger_channel_capacity,
                Some(comm.clone()),
            )
            .map_err(|e| MiscError::TrafficLogCreateError(csv_path.clone(), e.to_string()))?;
            log!(SystemLog::TrafficLoggingEnabled(csv_path));
            Some(Arc::new(logger))
        } else {
            None
        };

        let engine_config = EngineConfig {
            max_flows: config.ml.max_concurrent_flows,
            min_packets: config.ml.min_packets_for_inference,
            min_packets_floor: config.ml.min_packets_floor,
            batch_size: config.ml.inference_batch_size,
            inference_interval_secs: config.ml.inference_interval_secs,
            aggregator_window_secs: config.ml.aggregator_window_secs,
            confirmation_window_fraction: config.ml.confirmation_window_fraction,
        };

        let flow_limits = FlowLimits {
            max_packets_per_direction: config.ml.flow_max_packets_per_direction,
            max_periods: config.ml.flow_max_periods,
            idle_threshold_us: config.ml.flow_idle_threshold_us,
            bulk_min_packets: config.ml.flow_bulk_min_packets,
            bulk_min_bytes: config.ml.flow_bulk_min_bytes,
            idle_timeout_us: config.ml.flow_idle_timeout_us,
            terminated_timeout_us: config.ml.flow_terminated_timeout_us,
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

        let flow_statistics = Arc::new(FlowStatistics::new(ml_engine.clone()));
        let fusion_metrics = Arc::new(FusionMetrics::new());

        Ok(Self {
            health: Arc::new(health),
            ml_alert,
            ml_inference,
            ml_engine,
            flow_statistics,
            fusion_metrics,
            shutdowns: SegQueue::new(),
        })
    }

    pub async fn run(&self) -> Result<(), Error> {
        let health = self.health.clone();
        let ml_engine = self.ml_engine.clone();

        let health_shutdown = health.run(Duration::from_secs(3)).await;
        self.shutdowns.push(health_shutdown);

        let ml_shutdown = ml_engine.run().await;
        self.shutdowns.push(ml_shutdown);

        Ok(())
    }

    pub fn terminate(&self) {
        while let Some(shutdown) = self.shutdowns.pop() {
            if shutdown.send(()).is_err() {
                log!(SystemError::ShutdownSignalFailed);
            }
        }
    }
}
