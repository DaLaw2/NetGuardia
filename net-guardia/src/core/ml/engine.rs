//! ML engine — orchestrates flow tracking, feature extraction, adapter-
//! dispatched inference, and alert broadcast. Each inference tick cleans up
//! stale flows, gathers the latest batch, optionally logs a Flow Trace row,
//! and — when the inference source is Active — updates drift and runs
//! adapter-dispatched inference.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use macros::log;
use tokio::sync::oneshot;
use tokio::task::spawn_blocking;
use tokio::time::interval;

use super::aggregator::AttackAggregator;
use super::alert::MLAlert;
use super::drift_detector::DriftDetectorHandle;
use super::flow_tracker::{FlowData, FlowTracker};
use super::inference::Inference;
use super::traffic_logger::TrafficLogger;
use crate::interface::port::packet_sink::{PacketSink, PacketSinkFactory};
use crate::model::detection::flow_features::FlowFeatures;
use crate::model::detection::ml_detection::{EngineConfig, FlowKey, InferenceStats};
use crate::model::log::ml::MLLog;
use crate::model::monitoring::user_packet::UserPacket;

/// Divisor applied to "ticks per aggregator window" to derive the fallback
/// confirmations count: 2 means a default-behaviour detection must fire
/// across at least half the window's ticks before alerting.
const DEFAULT_CONFIRMATION_WINDOW_FRACTION: u64 = 2;

/// Hard floor on the per-flow packet count that gates ML inference for any
/// protocol / port combination that lacks an explicit low-packet override.
/// Prevents a misconfigured `min_packets` (0..=4) from feeding two-packet
/// flows into the model where the features carry almost no signal and the
/// false-alarm rate dominates. Protocols and ports that are meaningful at
/// very low packet counts (ICMP scans, DNS tunneling, C2 beacons) bypass
/// this floor through explicit overrides in `effective_min_packets`.
const ML_MIN_PACKETS_FLOOR: usize = 5;

/// Per-queue tracker. With symmetric hash in eBPF, both directions of a flow
/// land on the same queue, so per-queue trackers correctly see bidirectional flows.
/// `FlowTracker` itself is internally synchronized (DashMap), so the
/// per-queue handle is a plain `Arc`.
pub type ThreadTracker = Arc<FlowTracker>;

pub struct Engine {
    trackers: Vec<ThreadTracker>,
    inference_pipeline: Arc<Inference>,
    aggregator: AttackAggregator,
    drift_detector: DriftDetectorHandle,
    ml_alert: Arc<MLAlert>,
    min_packets: usize,
    /// Confirmations count used when the active manifest's label has no
    /// explicit `confirmations` override.
    default_confirmations: usize,
    batch_size: usize,
    inference_interval_secs: u64,
    traffic_logger: Option<Arc<TrafficLogger>>,
}

impl Engine {
    /// Build an Engine around an already-constructed Inference pipeline.
    /// The Inference's state (Dormant / Active / Error) is consulted per tick.
    pub fn new(
        inference_pipeline: Arc<Inference>,
        ml_alert: Arc<MLAlert>,
        drift_detector: DriftDetectorHandle,
        engine_config: EngineConfig,
        traffic_logger: Option<Arc<TrafficLogger>>,
        num_threads: u32,
    ) -> Self {
        let interval_secs = engine_config.inference_interval_secs.max(1);
        let ticks_per_window = engine_config.aggregator_window_secs / interval_secs;
        let default_confirmations = (ticks_per_window / DEFAULT_CONFIRMATION_WINDOW_FRACTION).max(1) as usize;
        let aggregator = AttackAggregator::new(engine_config.aggregator_window_secs);

        let max_flows_per_thread = engine_config.max_flows / (num_threads as usize).max(1);
        let trackers: Vec<ThreadTracker> = (0..num_threads)
            .map(|_| Arc::new(FlowTracker::new(max_flows_per_thread)))
            .collect();

        Self {
            trackers,
            inference_pipeline,
            aggregator,
            drift_detector,
            ml_alert,
            min_packets: engine_config.min_packets,
            default_confirmations,
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

    /// Directory the Flow Trace writer is rotating CSV files into.
    /// `None` when Flow Trace recording is disabled — the HTTP file-list
    /// and download handlers return a dormant response in that case.
    pub fn traffic_logger_directory(&self) -> Option<&std::path::Path> {
        self.traffic_logger.as_ref().map(|l| l.directory())
    }

    /// Protocol / port combinations whose traffic is overwhelmingly benign
    /// under tight structural constraints. Flows that match bypass ML
    /// inference entirely — they account for 40–60% of live traffic on a
    /// typical enterprise link and their feature vectors look almost
    /// identical, so running the model on them is pure cost.
    ///
    /// Structural constraints matter: "UDP/53 at any packet count" would
    /// miss DNS-tunneling attacks that pump hundreds of packets through
    /// the same 5-tuple. The rules here each pair a well-known benign
    /// protocol with the boundary beyond which the rule should no longer
    /// apply.
    fn is_strong_benign(flow_key: &FlowKey, fwd_count: usize, bwd_count: usize, total_bytes: u64) -> bool {
        match flow_key.protocol {
            // TCP/443 bidirectional — a TLS handshake has completed in both
            // directions, so this is almost always encrypted browsing rather
            // than a C2 / exfil beacon.
            6 if flow_key.dst_port == 443 => fwd_count > 0 && bwd_count > 0,
            // UDP/53 small DNS — a standard lookup fits in ≤4 packets (one
            // query, up to three response frames). Larger bursts get ML
            // scrutiny in case of DNS tunneling.
            17 if flow_key.dst_port == 53 => fwd_count + bwd_count <= 4,
            // UDP/123 NTP — a well-formed time sync is 48 bytes of payload
            // plus ≈ 28 bytes of IP/UDP headers (~76 B on the wire). Allow
            // up to 90 B average as a buffer; amplification attacks spike
            // the average size well past that boundary.
            17 if flow_key.dst_port == 123 => {
                let total_pkts = (fwd_count + bwd_count) as u64;
                total_pkts > 0 && total_bytes / total_pkts <= 90
            }
            _ => false,
        }
    }

    /// Protocol/port-aware min_packets: some traffic patterns are meaningful
    /// at very low packet counts and would be invisible to ML at the global
    /// threshold. Paths that fall through to `global` are additionally
    /// floored at `ML_MIN_PACKETS_FLOOR` so a misconfigured global setting
    /// can't feed near-empty flows into inference.
    fn effective_min_packets(flow_key: &FlowKey, global: usize) -> usize {
        let floored = global.max(ML_MIN_PACKETS_FLOOR);
        match flow_key.protocol {
            // ICMP: single-packet SYN scans, ping sweeps.
            1 => 1,
            // UDP
            17 => match flow_key.dst_port {
                53 => 1,
                123 => 2,
                3333 | 45700 => 2,
                _ => floored,
            },
            // TCP
            6 => match flow_key.dst_port {
                53 => 2,
                4444 | 8443 | 8080 | 1337 | 31337 => 2,
                3333 | 45700 => 2,
                _ => floored,
            },
            _ => floored,
        }
    }

    pub async fn run(self: Arc<Self>) -> oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            self.run_inference_loop(shutdown_rx).await;
        });
        shutdown_tx
    }

    async fn run_inference_loop(self: Arc<Self>, mut shutdown_rx: oneshot::Receiver<()>) {
        let mut ticker = interval(Duration::from_secs(self.inference_interval_secs));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {}
            }

            let engine = Arc::clone(&self);
            let _ = spawn_blocking(move || {
                engine.run_inference_tick();
            })
            .await;
        }
    }

    /// Phased tick: clean up stale flows, gather the uninferred batch
    /// (min-packet filtered), optionally write a Flow Trace row, and when
    /// the inference source is Active update drift then run inference.
    /// Dormant / Error states short-circuit before drift + inference.
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
            all_flows.extend(tracker.get_uninferred_flows().into_iter().filter(|flow| {
                let total_packets = flow.packet_count();
                total_packets >= Self::effective_min_packets(&flow.flow_key, self.min_packets)
                    && !Self::is_strong_benign(
                        &flow.flow_key,
                        flow.fwd_packets.len(),
                        flow.bwd_packets.len(),
                        flow.fwd_total_bytes + flow.bwd_total_bytes,
                    )
            }));
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

        if let Some(ref logger) = self.traffic_logger {
            self.log_traffic(&all_flows, logger);
        }

        if !self.inference_pipeline.is_active() {
            return;
        }

        self.update_drift(&all_flows);
        self.run_inference(&all_flows);
    }

    fn log_traffic(&self, flows: &[FlowData], logger: &TrafficLogger) {
        let feature_names = FlowFeatures::all_feature_names_owned();
        for flow in flows {
            let features = FlowFeatures::extract(flow, &feature_names);
            logger.log_row(features.to_csv_record());
        }
    }

    /// Update drift baseline — only called when inference state is Active,
    /// guaranteeing the ArcSwap snapshot the next `infer_batch` sees matches
    /// the features we just normalized against.
    fn update_drift(&self, batch: &[FlowData]) {
        let batch = &batch[..batch.len().min(self.batch_size)];
        let config = &self.inference_pipeline.config;
        for flow in batch {
            let features = FlowFeatures::extract(flow, &config.ae_feature_names);
            let normalized: Vec<f64> = features
                .features
                .iter()
                .zip(config.ae_scaler_mean.iter().zip(config.ae_scaler_std.iter()))
                .map(|(&val, (&mean, &std))| if std.abs() > 1e-12 { (val - mean) / std } else { 0.0 })
                .collect();
            self.drift_detector.update(normalized);
        }
    }

    fn run_inference(&self, flows: &[FlowData]) {
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

        let config = &self.inference_pipeline.config;
        for result in &results {
            if result.is_attack {
                let required_confirmations = result
                    .attack_type
                    .as_deref()
                    .and_then(|at| self.inference_pipeline.confirmations_for_attack_type(at))
                    .unwrap_or(self.default_confirmations);
                let should_alert = self.aggregator.should_alert(
                    &result.flow_key_raw,
                    result.confidence,
                    config.class_min_confidence,
                    required_confirmations,
                    config.alert_threshold_multiplier,
                );

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

        self.aggregator.cleanup();
    }
}

/// Adapter that exposes one `ThreadTracker` (per AF_XDP queue) as a `PacketSink`.
struct QueueTrackerSink {
    tracker: ThreadTracker,
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
    //! `effective_min_packets` coverage. Broader Engine behavior needs a
    //! flow-tracker harness and lives in integration-style tests elsewhere.

    use super::*;

    fn flow_key(protocol: u8, dst_port: u16) -> FlowKey {
        FlowKey {
            src_ip: [0; 16],
            dst_ip: [0; 16],
            src_port: 12345,
            dst_port,
            protocol,
            ip_version: 4,
        }
    }

    #[test]
    fn floor_applies_when_global_below_five() {
        // Bulk TCP / UDP with no low-packet override must not drop below 5
        // even if the operator sets a permissive global.
        assert_eq!(
            Engine::effective_min_packets(&flow_key(6, 443), 2),
            ML_MIN_PACKETS_FLOOR
        );
        assert_eq!(
            Engine::effective_min_packets(&flow_key(17, 500), 0),
            ML_MIN_PACKETS_FLOOR
        );
        // Uncommon protocol (SCTP) also honors the floor.
        assert_eq!(
            Engine::effective_min_packets(&flow_key(132, 9), 1),
            ML_MIN_PACKETS_FLOOR
        );
    }

    #[test]
    fn floor_respects_higher_global() {
        // A stricter global wins — the floor is a lower bound, not a clamp.
        assert_eq!(Engine::effective_min_packets(&flow_key(6, 443), 12), 12);
        assert_eq!(Engine::effective_min_packets(&flow_key(17, 500), 8), 8);
    }

    #[test]
    fn icmp_override_bypasses_floor() {
        // Single-packet ICMP scans must remain visible regardless of the floor.
        assert_eq!(Engine::effective_min_packets(&flow_key(1, 0), 100), 1);
    }

    #[test]
    fn low_packet_overrides_preserved() {
        // Every explicit low-packet override keeps its tuned value.
        assert_eq!(Engine::effective_min_packets(&flow_key(17, 53), 100), 1); // UDP DNS
        assert_eq!(Engine::effective_min_packets(&flow_key(17, 123), 100), 2); // UDP NTP
        assert_eq!(Engine::effective_min_packets(&flow_key(17, 3333), 100), 2); // UDP C2
        assert_eq!(Engine::effective_min_packets(&flow_key(17, 45700), 100), 2); // UDP C2
        assert_eq!(Engine::effective_min_packets(&flow_key(6, 53), 100), 2); // TCP DNS
        for port in [4444u16, 8443, 8080, 1337, 31337] {
            assert_eq!(Engine::effective_min_packets(&flow_key(6, port), 100), 2);
        }
        assert_eq!(Engine::effective_min_packets(&flow_key(6, 3333), 100), 2); // TCP C2
    }

    #[test]
    fn exact_floor_value_passes_through() {
        // At the floor boundary, no bump applied.
        assert_eq!(Engine::effective_min_packets(&flow_key(6, 443), 5), 5);
    }

    #[test]
    fn tls_bidirectional_flow_is_strong_benign() {
        // TCP/443 with traffic in both directions = completed TLS handshake.
        assert!(Engine::is_strong_benign(&flow_key(6, 443), 3, 2, 4096));
    }

    #[test]
    fn tls_unidirectional_flow_is_not_benign() {
        // Only outbound packets seen — handshake not completed. Could be
        // a SYN scan; keep it in the inference path.
        assert!(!Engine::is_strong_benign(&flow_key(6, 443), 5, 0, 200));
        assert!(!Engine::is_strong_benign(&flow_key(6, 443), 0, 5, 200));
    }

    #[test]
    fn tls_on_non_443_port_is_not_benign() {
        // TCP to 8443 is common for stealth C2 / alternate HTTPS; don't
        // whitelist without a port match.
        assert!(!Engine::is_strong_benign(&flow_key(6, 8443), 3, 2, 4096));
    }

    #[test]
    fn dns_small_query_is_strong_benign() {
        // Standard DNS: 1 query + up to 3 response packets.
        assert!(Engine::is_strong_benign(&flow_key(17, 53), 1, 1, 160));
        assert!(Engine::is_strong_benign(&flow_key(17, 53), 2, 2, 320));
    }

    #[test]
    fn dns_large_burst_is_not_benign() {
        // 5 packets and above — possible DNS tunneling.
        assert!(!Engine::is_strong_benign(&flow_key(17, 53), 3, 2, 400));
        assert!(!Engine::is_strong_benign(&flow_key(17, 53), 50, 50, 10_000));
    }

    #[test]
    fn ntp_standard_average_is_strong_benign() {
        // Well-formed NTP request + response, each ~76 B on wire.
        // 2 packets × ~80 B = 160 B total, avg 80 B.
        assert!(Engine::is_strong_benign(&flow_key(17, 123), 1, 1, 160));
    }

    #[test]
    fn ntp_amplification_is_not_benign() {
        // NTP monlist amplification: 1 query packet + many large responses.
        // 1 + 100 packets, 50 000 bytes → avg ~495 B, well above 90 B floor.
        assert!(!Engine::is_strong_benign(&flow_key(17, 123), 1, 100, 50_000));
    }

    #[test]
    fn empty_flow_does_not_divide_by_zero() {
        // Defensive: a zero-packet NTP flow should simply not match the
        // benign rule rather than panic.
        assert!(!Engine::is_strong_benign(&flow_key(17, 123), 0, 0, 0));
    }

    #[test]
    fn other_protocols_are_not_strong_benign() {
        // ICMP, SCTP, and unlisted UDP / TCP ports all fall through to ML.
        assert!(!Engine::is_strong_benign(&flow_key(1, 0), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(132, 9), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(17, 500), 10, 10, 1024));
        assert!(!Engine::is_strong_benign(&flow_key(6, 22), 10, 10, 1024));
    }
}
