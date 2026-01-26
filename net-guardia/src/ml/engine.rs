use std::sync::Arc;
use std::time::{Duration, Instant};

use macros::log;
use tokio::time::interval;

use super::config_loader::InferenceConfig;
use super::flow_tracker::FlowTracker;
use super::inference::Inference;
use super::model_loader::MLModels;

use crate::utils::packet_parser::parse_packet;
use crate::model::log::ml::MLLog;
use crate::model::ml_detection::{EngineStats, InferenceStats};

pub struct Engine {
    flow_tracker: Arc<FlowTracker>,
    inference_pipeline: Arc<Inference>,
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

        Self {
            flow_tracker,
            inference_pipeline,
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

            let flows = self
                .flow_tracker
                .get_flows_for_inference(self.min_packets);

            log!(
                MLLog::FlowStats{
                    total_flows,
                    flows_len: flows.len(),
                    min_packets: self.min_packets
                }
            );

            if !all_flows.is_empty() {
                let packet_counts: Vec<usize> = all_flows.iter().map(|f| f.packet_count()).collect();
                log!(MLLog::PacketCounts { counts: format!("{:?}", packet_counts) });
            }

            if flows.is_empty() {
                log!(MLLog::InferenceSkipped {
                    reason: format!(
                        "No flows with sufficient packets (total flows: {}, min packets: {})",
                        total_flows,
                        self.min_packets
                    )
                });
                continue;
            }

            let batch_size = flows.len().min(200);
            let batch = &flows[..batch_size];

            log!(MLLog::RunningInference{ size: batch_size });

            let results = self.inference_pipeline.infer_batch(batch);

            let elapsed_us = start.elapsed().as_micros() as u64;
            let stats = InferenceStats::from_results(&results, elapsed_us);

            if results.len() != batch_size {
                log!(MLLog::InferenceResults{ size: batch_size, len: results.len() });
            }

            log!(MLLog::InferenceCompleted {
                total_flows: stats.total_flows,
                malicious: stats.malicious_flows,
                benign: stats.benign_flows,
                duration_ms: (elapsed_us as f64 / 1000.0) as u32,
                throughput: stats.flows_per_second
            });

            for result in &results {
                if result.is_attack {
                    log!(MLLog::ThreatDetected {
                        flow: result.flow_key.clone(),
                        attack_type: result.attack_type.clone().unwrap_or_else(|| "UNKNOWN".to_string()),
                        confidence: result.confidence,
                        ae_score: result.ae_score,
                        rf_score: result.rf_score,
                        ensemble_score: result.ensemble_score,
                    });
                }
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
                log!(MLLog::ParsePacketFailed { len: packet_data.len() })
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