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

/// Per-queue tracker. With symmetric hash in eBPF, both directions of a flow
/// land on the same queue, so per-queue trackers correctly see bidirectional flows.
pub type ThreadTracker = Arc<Mutex<FlowTracker>>;

pub struct Engine {
    trackers: Vec<ThreadTracker>,
    inference_pipeline: Arc<Inference>,
    aggregator: Mutex<AttackAggregator>,
    ml_alert: Arc<MLAlert>,
    min_packets: usize,
    batch_size: usize,
    inference_interval_secs: u64,
    traffic_logger: Option<Arc<TrafficLogger>>,
}

impl Engine {
    pub fn new(
        models: Arc<MLModels>,
        config: Arc<InferenceConfig>,
        ml_alert: Arc<MLAlert>,
        engine_config: EngineConfig,
        traffic_logger: Option<Arc<TrafficLogger>>,
        num_threads: u32,
    ) -> Self {
        let inference_pipeline = Arc::new(Inference::new(models, config));

        let min_detections = ((engine_config.aggregator_window_secs / engine_config.inference_interval_secs) / 2).max(1) as usize;
        let aggregator = Mutex::new(AttackAggregator::new(engine_config.aggregator_window_secs, min_detections));

        let max_flows_per_thread = engine_config.max_flows / (num_threads as usize).max(1);
        let trackers: Vec<ThreadTracker> = (0..num_threads)
            .map(|_| Arc::new(Mutex::new(FlowTracker::new(max_flows_per_thread))))
            .collect();

        Self {
            trackers,
            inference_pipeline,
            aggregator,
            ml_alert,
            min_packets: engine_config.min_packets,
            batch_size: engine_config.batch_size,
            inference_interval_secs: engine_config.inference_interval_secs,
            traffic_logger,
        }
    }

    /// xsk_manager calls this per queue_id; with symmetric hash each queue has its own tracker.
    pub fn tracker(&self, queue_id: u32) -> &ThreadTracker {
        &self.trackers[queue_id as usize % self.trackers.len()]
    }

    pub fn trackers(&self) -> &[ThreadTracker] {
        &self.trackers
    }

    pub fn inference_interval_secs(&self) -> u64 {
        self.inference_interval_secs
    }

    pub fn has_traffic_logger(&self) -> bool {
        self.traffic_logger.is_some()
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
        let mut all_snapshots = Vec::new();
        let mut total_count = 0;

        // Phase 1: O(1) lock per tracker — just swap
        for tracker in &self.trackers {
            let mut t = tracker.lock();
            total_count += t.flow_count();
            all_snapshots.push(t.take_snapshot());
            // lock released here
        }

        // Phase 2: filter outside all locks — O(flows) but non-blocking
        let all_flows: Vec<FlowData> = all_snapshots.into_iter()
            .flat_map(|map| map.into_values())
            .filter(|flow| flow.packet_count() >= self.min_packets)
            .collect();

        log!(MLLog::FlowStats(
            total_count,
            all_flows.len(),
            self.min_packets,
            format!("{} trackers", self.trackers.len())
        ));

        if all_flows.is_empty() {
            return;
        }

        if let Some(ref logger) = self.traffic_logger {
            self.log_traffic(&all_flows, logger);
        } else {
            self.run_inference(&all_flows);
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

}
