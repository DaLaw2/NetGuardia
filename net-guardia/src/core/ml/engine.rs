use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use macros::log;
use tokio::sync::oneshot;
use tokio::time::interval;

use super::aggregator::AttackAggregator;
use super::config_loader::InferenceConfig;
use super::feature_extractor::FlowFeatures;
use super::flow_tracker::{FlowData, FlowTracker};
use super::inference::Inference;
use super::model_loader::MLModels;
use super::traffic_logger::TrafficLogger;

use super::alert::MLAlert;
use crate::model::log::ml::MLLog;
use crate::model::ml_detection::{EngineConfig, InferenceStats};
use crate::utils::packet_parser::parse_packet;

/// Single shared tracker for all queues. All ingress/egress XSK threads see the
/// same flow table, so both directions of a flow always find the same canonical key
/// regardless of which RSS queue they land on.
pub type SharedTracker = Arc<Mutex<FlowTracker>>;

pub struct Engine {
    tracker: SharedTracker,
    inference_pipeline: Arc<Inference>,
    aggregator: Mutex<AttackAggregator>,
    ml_alert: Arc<MLAlert>,
    min_packets: usize,
    batch_size: usize,
    inference_interval_secs: u64,
    flow_timeout_us: u64,
    traffic_logger: Option<Arc<TrafficLogger>>,
}

impl Engine {
    pub fn new(
        models: Arc<MLModels>,
        config: Arc<InferenceConfig>,
        ml_alert: Arc<MLAlert>,
        engine_config: EngineConfig,
        traffic_logger: Option<Arc<TrafficLogger>>,
        _num_threads: u32,
    ) -> Self {
        let inference_pipeline = Arc::new(Inference::new(models, config));

        let min_detections = ((engine_config.aggregator_window_secs / engine_config.inference_interval_secs) / 2).max(1) as usize;
        let aggregator = Mutex::new(AttackAggregator::new(engine_config.aggregator_window_secs, min_detections));

        let tracker = Arc::new(Mutex::new(FlowTracker::new(engine_config.max_flows)));

        Self {
            tracker,
            inference_pipeline,
            aggregator,
            ml_alert,
            min_packets: engine_config.min_packets,
            batch_size: engine_config.batch_size,
            inference_interval_secs: engine_config.inference_interval_secs,
            flow_timeout_us: engine_config.flow_timeout_us,
            traffic_logger,
        }
    }

    /// xsk_manager calls this per queue_id; all queues share the same tracker.
    pub fn tracker(&self, _queue_id: u32) -> &SharedTracker {
        &self.tracker
    }

    pub fn shared_tracker(&self) -> &SharedTracker {
        &self.tracker
    }

    pub async fn run(self: Arc<Self>) -> oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            self.run_inference_loop(shutdown_rx).await;
        });
        shutdown_tx
    }

    async fn run_inference_loop(&self, mut shutdown_rx: oneshot::Receiver<()>) {
        let mut ticker = interval(Duration::from_secs(self.inference_interval_secs));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {}
            }

            self.run_inference_tick();
        }
    }

    fn run_inference_tick(&self) {
        let all_flows;
        let total_count;

        if self.traffic_logger.is_some() {
            // Logging mode: drain flows that have enough packets so each flow is logged once.
            // Flows below min_packets stay in the tracker to accumulate more data.
            let mut t = self.tracker.lock();
            total_count = t.flow_count();
            all_flows = t.drain_flows_for_logging(self.min_packets);
        } else {
            // Inference mode: snapshot current state, clean up afterwards.
            let t = self.tracker.lock();
            total_count = t.flow_count();
            all_flows = t.get_flows_for_inference(self.min_packets);
        }

        log!(MLLog::FlowStats(
            total_count,
            all_flows.len(),
            self.min_packets,
            "shared tracker".to_string()
        ));

        if all_flows.is_empty() {
            if self.traffic_logger.is_none() {
                self.tracker.lock().cleanup_old_flows(self.flow_timeout_us);
            }
            return;
        }

        if let Some(ref logger) = self.traffic_logger {
            self.log_traffic(&all_flows, logger);
        } else {
            self.run_inference(&all_flows);
            self.tracker.lock().cleanup_old_flows(self.flow_timeout_us);
        }
    }

    fn log_traffic(&self, flows: &[FlowData], logger: &TrafficLogger) {
        let feature_names = FlowFeatures::all_feature_names_owned();
        for flow in flows {
            let features = FlowFeatures::extract(flow, &feature_names);
            logger.log_row(features.to_csv_record());
        }
    }

    fn run_inference(&self, flows: &[FlowData]) {
        let batch = &flows[..flows.len().min(self.batch_size)];

        log!(MLLog::RunningInference(batch.len()));

        let start = Instant::now();
        let results = self.inference_pipeline.infer_batch(batch);
        let elapsed_us = start.elapsed().as_micros() as u64;

        let stats = InferenceStats::from_results(&results, elapsed_us);

        if results.len() != batch.len() {
            log!(MLLog::InferenceResults(batch.len(), results.len()));
        }

        log!(MLLog::InferenceCompleted(
            stats.total_flows,
            stats.malicious_flows,
            stats.benign_flows,
            (elapsed_us as f64 / 1000.0) as u32,
            stats.flows_per_second
        ));

        {
            let mut aggregator = self.aggregator.lock();
            for result in &results {
                if result.is_attack {
                    let should_alert =
                        aggregator.should_alert(&result.flow_key_raw, result.ae_score, result.threshold);

                    if should_alert {
                        log!(MLLog::ThreatDetected(
                            format!("{:?}", result.direction),
                            result.flow_key.clone(),
                            result.attack_type.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
                            result.confidence,
                            result.ae_score,
                        ));

                        self.ml_alert.broadcast_alert(result);
                    }
                }
            }

            aggregator.cleanup();
        }
    }

    /// Called by XSK threads. Lock is per-thread, uncontended on hot path.
    pub fn process_packet(tracker: &Mutex<FlowTracker>, packet_data: &[u8], is_ingress: bool) {
        match parse_packet(packet_data) {
            Some((packet_info, _)) => {
                tracker.lock().process_packet(packet_info, is_ingress);
            }
            None => log!(MLLog::ParsePacketFailed(packet_data.len())),
        }
    }
}
