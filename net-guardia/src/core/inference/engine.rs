use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use macros::log;
use tokio::sync::oneshot;
use tokio::task::spawn_blocking;
use tokio::time::interval;

use super::alert::MLAlert;
use super::drift_detector::DriftDetectorHandle;
use super::runner::Inference;
use crate::core::inference::aggregator::AttackAggregator;
use crate::core::inference::flow_tracker::FlowTracker;
use crate::domain::common::config::constants::KNOWN_C2_PORTS;
use crate::domain::data_plane::user_packet::UserPacket;
use crate::domain::detection::flow_features::FlowFeatures;
use crate::domain::detection::flow_tracker::{FlowLimits, FlowSnapshot};
use crate::domain::detection::log::MLLog;
use crate::domain::detection::ml_detection::{FlowKey, InferenceStats};
use crate::interface::data_plane::packet_sink::{PacketSink, PacketSinkFactory};
use crate::interface::detection::flow_trace_sink::FlowTraceSink;

const ICMP_PROTOCOL: u8 = 1;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DNS_PORT: u16 = 53;
const HTTPS_PORT: u16 = 443;
const NTP_PORT: u16 = 123;
const NTP_MAX_AVG_PACKET_BYTES: u64 = 90;
const ALERT_THRESHOLD_MULTIPLIER: f32 = 1.2;

pub struct EngineConfig {
    pub max_flows: usize,
    pub min_packets: usize,
    pub min_packets_floor: usize,
    pub batch_size: usize,
    pub inference_interval_secs: u64,
    pub aggregator_window_secs: u64,
    pub confirmation_window_fraction: u64,
}

pub struct Engine {
    trackers: Vec<Arc<FlowTracker>>,
    inference_pipeline: Arc<Inference>,
    aggregator: AttackAggregator,
    drift_detector: DriftDetectorHandle,
    ml_alert: Arc<MLAlert>,
    min_packets: usize,
    min_packets_floor: usize,
    default_confirmations: usize,
    batch_size: usize,
    inference_interval_secs: u64,
    flow_trace_sink: Option<Arc<dyn FlowTraceSink>>,
}

impl Engine {
    pub fn new(
        inference_pipeline: Arc<Inference>,
        ml_alert: Arc<MLAlert>,
        drift_detector: DriftDetectorHandle,
        engine_config: EngineConfig,
        flow_limits: FlowLimits,
        flow_trace_sink: Option<Arc<dyn FlowTraceSink>>,
        num_threads: u32,
    ) -> Self {
        let interval_secs = engine_config.inference_interval_secs.max(1);
        let ticks_per_window = engine_config.aggregator_window_secs / interval_secs;
        let default_confirmations =
            (ticks_per_window / engine_config.confirmation_window_fraction.max(1)).max(1) as usize;
        let aggregator = AttackAggregator::new(engine_config.aggregator_window_secs, engine_config.max_flows);

        let max_flows_per_thread = engine_config.max_flows / (num_threads as usize).max(1);
        let trackers: Vec<Arc<FlowTracker>> = (0..num_threads)
            .map(|_| Arc::new(FlowTracker::new(max_flows_per_thread, flow_limits)))
            .collect();

        Self {
            trackers,
            inference_pipeline,
            aggregator,
            drift_detector,
            ml_alert,
            min_packets: engine_config.min_packets,
            min_packets_floor: engine_config.min_packets_floor.max(1),
            default_confirmations,
            batch_size: engine_config.batch_size,
            inference_interval_secs: engine_config.inference_interval_secs,
            flow_trace_sink,
        }
    }

    pub fn tracker(&self, queue_id: u32) -> &Arc<FlowTracker> {
        &self.trackers[queue_id as usize % self.trackers.len()]
    }

    pub fn trackers(&self) -> &[Arc<FlowTracker>] {
        &self.trackers
    }

    pub fn inference_interval_secs(&self) -> u64 {
        self.inference_interval_secs
    }

    pub fn has_traffic_logger(&self) -> bool {
        self.flow_trace_sink.is_some()
    }

    pub fn traffic_logger_directory(&self) -> Option<&Path> {
        self.flow_trace_sink.as_ref().map(|sink| sink.directory())
    }

    fn is_strong_benign(flow_key: &FlowKey, fwd_count: usize, bwd_count: usize, total_bytes: u64) -> bool {
        match flow_key.protocol {
            TCP_PROTOCOL if flow_key.dst_port == HTTPS_PORT => fwd_count > 0 && bwd_count > 0,
            UDP_PROTOCOL if flow_key.dst_port == DNS_PORT => fwd_count + bwd_count <= 4,
            UDP_PROTOCOL if flow_key.dst_port == NTP_PORT => {
                let total_pkts = (fwd_count + bwd_count) as u64;
                total_pkts > 0 && total_bytes / total_pkts <= NTP_MAX_AVG_PACKET_BYTES
            }
            _ => false,
        }
    }

    fn effective_min_packets(flow_key: &FlowKey, global: usize, floor: usize) -> usize {
        let floored = global.max(floor.max(1));
        match flow_key.protocol {
            ICMP_PROTOCOL => 1,
            UDP_PROTOCOL => match flow_key.dst_port {
                DNS_PORT => 1,
                NTP_PORT => 2,
                3333 | 45700 => 2,
                _ => floored,
            },
            TCP_PROTOCOL => match flow_key.dst_port {
                DNS_PORT => 2,
                3333 | 45700 => 2,
                port if KNOWN_C2_PORTS.contains(&port) => 2,
                _ => floored,
            },
            _ => floored,
        }
    }

    pub async fn run(self: Arc<Self>, mut shutdown_rx: oneshot::Receiver<()>) {
        let mut ticker = interval(Duration::from_secs(self.inference_interval_secs));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {}
            }

            let engine = Arc::clone(&self);
            if let Err(err) = spawn_blocking(move || {
                engine.run_inference_tick();
            })
            .await
            {
                log!(MLLog::InferenceTaskJoinFailed(err.to_string()));
            }
        }
    }

    fn run_inference_tick(&self) {
        let mut all_flows = Vec::new();
        let mut total_count = 0;
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        for tracker in &self.trackers {
            tracker.cleanup_stale_flows(now_us);
        }

        for tracker in &self.trackers {
            total_count += tracker.flow_count();
            all_flows.extend(
                tracker
                    .get_uninferred_flows(self.batch_size)
                    .into_iter()
                    .filter(|flow| {
                        let total_packets = flow.packet_count;
                        total_packets
                            >= Self::effective_min_packets(&flow.flow_key, self.min_packets, self.min_packets_floor)
                            && !Self::is_strong_benign(
                                &flow.flow_key,
                                flow.fwd_packet_count,
                                flow.bwd_packet_count,
                                flow.total_bytes,
                            )
                    }),
            );
        }

        log!(MLLog::FlowStats(
            total_count,
            all_flows.len(),
            self.min_packets,
            format!("{} trackers", self.trackers.len())
        ));

        if all_flows.is_empty() {
            return;
        }

        if let Some(ref sink) = self.flow_trace_sink {
            self.log_traffic(&all_flows, sink.as_ref());
        }

        if !self.inference_pipeline.is_active() {
            return;
        }

        self.update_drift(&all_flows);
        self.run_inference(&all_flows);
    }

    fn log_traffic(&self, flows: &[FlowSnapshot], sink: &dyn FlowTraceSink) {
        let feature_names = FlowFeatures::all_feature_names_owned();
        for flow in flows {
            let features = FlowFeatures::extract_from_stats(&flow.feature_stats, feature_names);
            sink.log_row(features.to_csv_line());
        }
    }

    fn update_drift(&self, batch: &[FlowSnapshot]) {
        let batch = &batch[..batch.len().min(self.batch_size)];
        let config = &self.inference_pipeline.config;
        for flow in batch {
            let features = FlowFeatures::extract_from_stats(&flow.feature_stats, &config.ae_feature_names);
            let normalized: Vec<f64> = features
                .features
                .iter()
                .zip(config.ae_scaler_mean.iter().zip(config.ae_scaler_std.iter()))
                .map(|(&val, (&mean, &std))| if std.abs() > 1e-12 { (val - mean) / std } else { 0.0 })
                .collect();
            self.drift_detector.update(normalized);
        }
    }

    fn run_inference(&self, flows: &[FlowSnapshot]) {
        let batch = &flows[..flows.len().min(self.batch_size)];

        log!(MLLog::RunningInference(batch.len()));

        let start = Instant::now();
        let results = self.inference_pipeline.infer_batch(batch);
        let elapsed_us = start.elapsed().as_micros() as u64;

        let stats = InferenceStats::from_results(&results, elapsed_us);
        self.inference_pipeline.record_tick_qps(stats.flows_per_second);

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

        for result in &results {
            if result.is_attack {
                let required_confirmations = result
                    .attack_type
                    .and_then(|attack_type| self.inference_pipeline.confirmations_for_attack_type(attack_type))
                    .unwrap_or(self.default_confirmations);
                let should_alert = self.aggregator.should_alert(
                    &result.flow_key_raw,
                    result.confidence,
                    result.alert_threshold,
                    required_confirmations,
                    ALERT_THRESHOLD_MULTIPLIER,
                );

                if should_alert {
                    log!(MLLog::ThreatDetected(
                        format!("{:?}", result.direction),
                        result.flow_key.clone(),
                        result
                            .attack_type
                            .map(|attack_type| attack_type.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        result.confidence,
                        result.ae_score,
                    ));

                    self.ml_alert.broadcast_alert(result);
                }
            }
        }

        self.aggregator.cleanup();
    }
}

struct QueueTrackerSink {
    tracker: Arc<FlowTracker>,
}

impl PacketSink for QueueTrackerSink {
    fn process_packet(&self, packet: UserPacket, is_ingress: bool) {
        self.tracker.process_packet(packet, is_ingress);
    }
}

impl PacketSinkFactory for Engine {
    fn sink_for_queue(&self, queue_id: u32) -> Option<Arc<dyn PacketSink>> {
        let tracker = self.tracker(queue_id).clone();
        Some(Arc::new(QueueTrackerSink { tracker }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_plane::ip_version::IpVersion;

    fn flow_key(protocol: u8, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 12345,
            dst_port,
            protocol,
            ip_version: IpVersion::V4,
        }
    }

    const TEST_FLOOR: usize = 5;

    #[test]
    fn floor_applies_when_global_below_five() {
        assert_eq!(
            Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, HTTPS_PORT), 2, TEST_FLOOR),
            TEST_FLOOR
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, 500), 0, TEST_FLOOR),
            TEST_FLOOR
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(132, 9), 1, TEST_FLOOR),
            TEST_FLOOR
        );
    }

    #[test]
    fn floor_respects_higher_global() {
        assert_eq!(
            Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, HTTPS_PORT), 12, TEST_FLOOR),
            12
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, 500), 8, TEST_FLOOR),
            8
        );
    }

    #[test]
    fn icmp_override_bypasses_floor() {
        assert_eq!(
            Engine::effective_min_packets(&flow_key(ICMP_PROTOCOL, 0), 100, TEST_FLOOR),
            1
        );
    }

    #[test]
    fn low_packet_overrides_preserved() {
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, DNS_PORT), 100, TEST_FLOOR),
            1
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, NTP_PORT), 100, TEST_FLOOR),
            2
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, 3333), 100, TEST_FLOOR),
            2
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(UDP_PROTOCOL, 45700), 100, TEST_FLOOR),
            2
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, DNS_PORT), 100, TEST_FLOOR),
            2
        );
        for port in [4444u16, 8443, 8080, 1337, 31337] {
            assert_eq!(
                Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, port), 100, TEST_FLOOR),
                2
            );
        }
        assert_eq!(
            Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, 3333), 100, TEST_FLOOR),
            2
        );
    }

    #[test]
    fn exact_floor_value_passes_through() {
        assert_eq!(
            Engine::effective_min_packets(&flow_key(TCP_PROTOCOL, HTTPS_PORT), 5, TEST_FLOOR),
            5
        );
    }

    #[test]
    fn tls_bidirectional_flow_is_strong_benign() {
        assert!(Engine::is_strong_benign(
            &flow_key(TCP_PROTOCOL, HTTPS_PORT),
            3,
            2,
            4096
        ));
    }

    #[test]
    fn tls_unidirectional_flow_is_not_benign() {
        assert!(!Engine::is_strong_benign(
            &flow_key(TCP_PROTOCOL, HTTPS_PORT),
            5,
            0,
            200
        ));
        assert!(!Engine::is_strong_benign(
            &flow_key(TCP_PROTOCOL, HTTPS_PORT),
            0,
            5,
            200
        ));
    }

    #[test]
    fn tls_on_non_443_port_is_not_benign() {
        assert!(!Engine::is_strong_benign(&flow_key(TCP_PROTOCOL, 8443), 3, 2, 4096));
    }

    #[test]
    fn dns_small_query_is_strong_benign() {
        assert!(Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, DNS_PORT), 1, 1, 160));
        assert!(Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, DNS_PORT), 2, 2, 320));
    }

    #[test]
    fn dns_large_burst_is_not_benign() {
        assert!(!Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, DNS_PORT), 3, 2, 400));
        assert!(!Engine::is_strong_benign(
            &flow_key(UDP_PROTOCOL, DNS_PORT),
            50,
            50,
            10_000
        ));
    }

    #[test]
    fn ntp_standard_average_is_strong_benign() {
        assert!(Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, NTP_PORT), 1, 1, 160));
    }

    #[test]
    fn ntp_amplification_is_not_benign() {
        assert!(!Engine::is_strong_benign(
            &flow_key(UDP_PROTOCOL, NTP_PORT),
            1,
            100,
            50_000
        ));
    }

    #[test]
    fn empty_flow_does_not_divide_by_zero() {
        assert!(!Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, NTP_PORT), 0, 0, 0));
    }

    #[test]
    fn other_protocols_are_not_strong_benign() {
        assert!(!Engine::is_strong_benign(&flow_key(ICMP_PROTOCOL, 0), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(132, 9), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(UDP_PROTOCOL, 500), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(TCP_PROTOCOL, 22), 10, 10, 1024));
    }
}
