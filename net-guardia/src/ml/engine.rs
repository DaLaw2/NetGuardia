use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

use macros::log;
use tokio::time::interval;

use super::config_loader::InferenceConfig;
use super::flow_tracker::FlowTracker;
use super::inference::Inference;
use super::model_loader::MLModels;
use super::aggregator::AttackAggregator;

use crate::utils::packet_parser::parse_packet;
use crate::model::log::ml::MLLog;
use crate::model::ml_detection::{EngineStats, InferenceStats};

pub struct Engine {
    flow_tracker: Arc<FlowTracker>,
    inference_pipeline: Arc<Inference>,
    aggregator: Arc<Mutex<AttackAggregator>>,
    min_packets: usize,
    inference_interval_secs: u64,
}

impl Engine {
    pub fn new(
        models: Arc<MLModels>,
        config: Arc<InferenceConfig>,
        max_flows: usize,
        min_packets: usize,
        interval_secs: u64,
    ) -> Self {
        let flow_tracker = Arc::new(FlowTracker::new(max_flows));
        let inference_pipeline = Arc::new(Inference::new(models, config));

        let aggregator = Arc::new(Mutex::new(AttackAggregator::new(30, 10)));

        Self {
            flow_tracker,
            inference_pipeline,
            aggregator,
            min_packets,
            inference_interval_secs: interval_secs,
        }
    }

    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.run_inference_loop().await;
        })
    }

    pub fn get_flow_tracker(&self) -> Arc<FlowTracker> {
        self.flow_tracker.clone()
    }

    async fn run_inference_loop(&self) {
        let mut ticker = interval(Duration::from_secs(self.inference_interval_secs));

        loop {
            ticker.tick().await;

            let start = Instant::now();

            let total_flows = self.flow_tracker.flow_count();
            let all_flows = self.flow_tracker.get_flows_snapshot();
            let packet_counts: Vec<usize> = all_flows.iter().map(|f| f.packet_count()).collect();

            let flows = self
                .flow_tracker
                .get_flows_for_inference(self.min_packets);

            log!(
                MLLog::FlowStats(
                    total_flows,
                    flows.len(),
                    self.min_packets,
                    format!("{:?}", packet_counts)
                )
            );

            if flows.is_empty() {
                log!(
                    MLLog::InferenceSkipped(
                        format!(
                            "No flows with sufficient packets (total flows: {}, min packets: {})",
                            total_flows,
                            self.min_packets
                        )
                    )
                );
                continue;
            }

            let batch_size = flows.len().min(200);
            let batch = &flows[..batch_size];

            log!(MLLog::RunningInference(batch_size));

            let results = self.inference_pipeline.infer_batch(batch);

            let elapsed_us = start.elapsed().as_micros() as u64;
            let stats = InferenceStats::from_results(&results, elapsed_us);

            if results.len() != batch_size {
                log!(MLLog::InferenceResults(batch_size, results.len()));
            }

            log!(
                MLLog::InferenceCompleted(
                    stats.total_flows,
                    stats.malicious_flows,
                    stats.benign_flows,(elapsed_us as f64 / 1000.0) as u32,
                    stats.flows_per_second
                )
            );

            if let Ok(mut aggregator) = self.aggregator.lock() {
                for result in &results {
                    if result.is_attack {
                        let should_alert = aggregator.should_alert(
                            &result.flow_key_raw,
                            result.ensemble_score,
                            self.inference_pipeline.config.threshold as f32,
                        );

                        if should_alert {
                            log!(
                                MLLog::ThreatDetected(
                                    result.flow_key.clone(),
                                    result.attack_type.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
                                    result.confidence,
                                    result.ae_score,
                                    result.rf_score,
                                    result.ensemble_score,
                                )
                            );
                        }
                    }
                }

                aggregator.cleanup();
            }

            self.flow_tracker.cleanup_old_flows(60_000_000);
        }
    }

    pub fn process_packet(&self, packet_data: &[u8]) {
        match parse_packet(packet_data) {
            Some(packet_info) => {
                self.flow_tracker.process_packet(packet_info);
            }
            None => {
                log!(MLLog::ParsePacketFailed(packet_data.len()))
            }
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

    pub fn process(&self, packet_data: &[u8]) {
        self.ml_engine.process_packet(packet_data);
    }

    pub fn process_batch(&self, packets: &[Vec<u8>]) {
        for packet in packets {
            self.process(packet);
        }
    }
}