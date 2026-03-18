use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use macros::log;
use tokio::sync::oneshot;
use tokio::time::interval;

use super::aggregator::AttackAggregator;
use super::config_loader::InferenceConfig;
use super::feature_extractor::FlowFeatures;
use super::flow_tracker::FlowTracker;
use super::inference::Inference;
use super::model_loader::MLModels;
use super::traffic_logger::TrafficLogger;

use crate::core::infrastructure::ml_alert::MLAlert;
use crate::model::log::ml::MLLog;
use crate::model::ml_detection::{EngineStats, InferenceStats};
use crate::utils::packet_parser::parse_packet;

pub struct Engine {
    flow_tracker: Arc<FlowTracker>,
    inference_pipeline: Arc<Inference>,
    aggregator: Arc<Mutex<AttackAggregator>>,
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
        max_flows: usize,
        min_packets: usize,
        batch_size: usize,
        interval_secs: u64,
        window_secs: u64,
        traffic_logger: Option<Arc<TrafficLogger>>,
    ) -> Self {
        let flow_tracker = Arc::new(FlowTracker::new(max_flows));
        let inference_pipeline = Arc::new(Inference::new(models, config));

        let min_detections = ((window_secs / interval_secs) / 2).max(1) as usize;
        let aggregator = Arc::new(Mutex::new(AttackAggregator::new(window_secs, min_detections)));

        Self {
            flow_tracker,
            inference_pipeline,
            aggregator,
            ml_alert,
            min_packets,
            batch_size,
            inference_interval_secs: interval_secs,
            traffic_logger,
        }
    }

    pub async fn run(self: Arc<Self>) -> oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            self.run_inference_loop(shutdown_rx).await;
        });
        shutdown_tx
    }

    pub fn get_flow_tracker(&self) -> Arc<FlowTracker> {
        self.flow_tracker.clone()
    }

    async fn run_inference_loop(&self, mut shutdown_rx: oneshot::Receiver<()>) {
        let mut ticker = interval(Duration::from_secs(self.inference_interval_secs));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {}
            }

            let total_flows = self.flow_tracker.flow_count();
            let all_flows = self.flow_tracker.get_flows_snapshot();
            let packet_counts: Vec<usize> = all_flows.iter().map(|f| f.packet_count()).collect();

            let flows = self.flow_tracker.get_flows_for_inference(self.min_packets);

            log!(MLLog::FlowStats(
                total_flows,
                flows.len(),
                self.min_packets,
                format!("{:?}", packet_counts)
            ));

            if flows.is_empty() {
                log!(MLLog::InferenceSkipped(format!(
                    "No flows with sufficient packets (total flows: {}, min packets: {})",
                    total_flows, self.min_packets
                )));
                continue;
            }

            if let Some(ref logger) = self.traffic_logger {
                let feature_names = FlowFeatures::all_feature_names_owned();
                for flow in &flows {
                    let features = FlowFeatures::extract(flow, &feature_names);
                    logger.log_row(features.to_csv_record());
                }
                self.flow_tracker.cleanup_old_flows(60_000_000);
                continue;
            }

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

            if let Ok(mut aggregator) = self.aggregator.lock() {
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

            self.flow_tracker.cleanup_old_flows(60_000_000);
        }
    }

    pub fn process_packet(&self, packet_data: &[u8], is_ingress: bool) {
        match parse_packet(packet_data) {
            Some((packet_info, payload_start)) => {
                let payload = packet_data.get(payload_start..).unwrap_or(&[]);
                self.flow_tracker.process_packet(packet_info, is_ingress, payload);
            }
            None => log!(MLLog::ParsePacketFailed(packet_data.len())),
        }
    }

    pub fn get_stats(&self) -> EngineStats {
        EngineStats {
            active_flows: self.flow_tracker.flow_count(),
        }
    }
}

pub struct PacketProcessor {
    ml_engine: Arc<Engine>,
}

impl PacketProcessor {
    pub fn new(ml_engine: Arc<Engine>) -> Self {
        Self { ml_engine }
    }

    pub fn process(&self, packet_data: &[u8], is_ingress: bool) {
        self.ml_engine.process_packet(packet_data, is_ingress);
    }

    pub fn process_batch(&self, packets: &[Vec<u8>], is_ingress: bool) {
        for packet in packets {
            self.process(packet, is_ingress);
        }
    }
}
