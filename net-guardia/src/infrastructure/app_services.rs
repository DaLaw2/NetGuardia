use std::sync::Arc;
use std::time::Duration;

use crossbeam::queue::SegQueue;
use macros::log;
use tokio::sync::oneshot;

use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::health::SystemHealth;
use crate::core::ml::alert::MLAlert;
use crate::infrastructure::statistics::FlowStatistics;
use crate::core::ml::config_loader::InferenceConfig;
use crate::core::ml::engine::Engine;
use crate::model::ml_detection::EngineConfig;
use crate::core::ml::feature_extractor::FlowFeatures;
use crate::core::ml::model_loader::MLModels;
use crate::model::error::misc::MiscError;
use crate::model::error::system::SystemError;
use crate::model::error::Error;
use crate::model::log::system::SystemLog;
use crate::core::ml::traffic_logger::TrafficLogger;

/// Application-level service orchestrator.
/// Holds all runtime services (health monitoring, ML inference, flow statistics)
/// and manages their lifecycle (start/shutdown).
pub struct AppServices {
    pub health: Arc<SystemHealth>,
    pub ml_alert: Arc<MLAlert>,
    pub ml_models: Arc<MLModels>,
    pub ml_engine: Arc<Engine>,
    pub flow_statistics: Arc<FlowStatistics>,
    shutdowns: SegQueue<oneshot::Sender<()>>,
}

impl AppServices {
    pub fn new(app_config: Arc<AppConfig>, inference_config: Arc<InferenceConfig>) -> Result<Self, Error> {
        let health = SystemHealth::new(app_config.clone())?;

        let ml_models = Arc::new(MLModels::load_models(&app_config, &inference_config)?);
        let ml_alert = Arc::new(MLAlert::new());

        let traffic_logger = if app_config.inference.traffic_logging_mode {
            let csv_path = app_config.inference.traffic_log_csv_path.clone();
            let mut header = FlowFeatures::all_feature_names_owned();
            header.push("Label".to_string());
            let logger = TrafficLogger::new(&csv_path, header)
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
            ml_models.clone(),
            inference_config.clone(),
            ml_alert.clone(),
            engine_config,
            traffic_logger,
            app_config.network.combined_queue_count,
        ));

        let flow_statistics = Arc::new(FlowStatistics::new(ml_engine.clone()));

        Ok(Self {
            health: Arc::new(health),
            ml_alert,
            ml_models,
            ml_engine,
            flow_statistics,
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
