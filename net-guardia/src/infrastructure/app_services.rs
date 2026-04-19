use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::core::detection::metrics::FusionMetrics;
use crate::core::ml::adapter::ModelSourceState;
use crate::core::ml::alert::MLAlert;
use crate::core::ml::drift_detector::DriftDetectorHandle;
use crate::core::ml::engine::Engine;
use crate::core::ml::inference::Inference;
use crate::core::ml::manifest::ModelManifest;
use crate::core::ml::model_loader::build_adapter;
use crate::core::ml::traffic_logger::{RotationPolicy, TrafficLogger};
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::statistics::FlowStatistics;
use crate::model::config::constants::{MANIFEST_FILENAME, MODELS_DIR};
use crate::model::detection::flow_features::FlowFeatures;
use crate::model::detection::ml_detection::EngineConfig;
use crate::model::detection::model_source::ModelInfo;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;
use crate::model::error::system::SystemError;
use crate::model::log::ml::MLLog;
use crate::model::log::system::SystemLog;
use crate::model::system::config::MLInferenceConfig;
use crate::model::system::health::EbpfHealth;

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
        app_config: Arc<AppConfig>,
        inference_config: Arc<MLInferenceConfig>,
        ml_manifest: Option<ModelManifest>,
        drift_detector: DriftDetectorHandle,
        ebpf_health: Arc<ArcSwap<EbpfHealth>>,
        comm: Arc<CommunicationManager>,
    ) -> Result<Self, Error> {
        let health = SystemHealth::new(app_config.clone(), ebpf_health)?;

        let batch_size = app_config.inference.inference_batch_size;

        let initial_state = match ml_manifest.as_ref() {
            Some(manifest) => {
                let manifest_path = PathBuf::from(MODELS_DIR).join(MANIFEST_FILENAME);
                match build_adapter(manifest, Some(&manifest_path), &inference_config, batch_size) {
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

        let ml_inference = Arc::new(Inference::new(initial_state, inference_config.clone()));
        let ml_alert = Arc::new(MLAlert::new());

        let traffic_logger = if app_config.inference.traffic_logging_mode {
            let csv_path = app_config.inference.traffic_log_csv_path.clone();
            let mut header = FlowFeatures::all_feature_names_owned();
            header.push("Label".to_string());
            let base_path = PathBuf::from(&csv_path);
            let policy = RotationPolicy {
                max_file_bytes: app_config.inference.flow_trace_max_file_bytes,
                max_file_age: Duration::from_secs(app_config.inference.flow_trace_max_file_age_secs),
                total_budget_bytes: app_config.inference.flow_trace_total_budget_bytes,
            };
            let logger = TrafficLogger::new(&base_path, header, policy, Some(comm.clone()))
                .map_err(|e| MiscError::TrafficLogCreateError(csv_path.clone(), e.to_string()))?;
            log!(SystemLog::TrafficLoggingEnabled(csv_path));
            Some(Arc::new(logger))
        } else {
            None
        };

        let engine_config = EngineConfig {
            max_flows: app_config.inference.max_concurrent_flows,
            min_packets: app_config.inference.min_packets_for_inference,
            batch_size: app_config.inference.inference_batch_size,
            inference_interval_secs: app_config.inference.inference_interval_secs,
            aggregator_window_secs: app_config.inference.aggregator_window_secs,
        };

        let ml_engine = Arc::new(Engine::new(
            ml_inference.clone(),
            ml_alert.clone(),
            drift_detector,
            engine_config,
            traffic_logger,
            app_config.network.combined_queue_count,
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
