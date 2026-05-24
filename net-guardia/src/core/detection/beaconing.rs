use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use macros::log;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::attack_type::CanonicalAttackType;
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::log::DetectionLog;

pub struct BeaconingDetector {
    state: BeaconingState,
    alert_rx: broadcast::Receiver<FlowObservation>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    analysis_interval_secs: u64,
}

impl BeaconingDetector {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        alert_rx: broadcast::Receiver<FlowObservation>,
        detection_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        let cfg = app_config.load();
        let beaconing = &cfg.detection.beaconing;
        Self {
            state: BeaconingState::new(
                beaconing.min_observations,
                beaconing.cv_threshold,
                beaconing.max_cache_entries,
                beaconing.max_timestamps_per_flow,
                beaconing.expiry_secs,
                beaconing.alert_cooldown_secs,
            ),
            alert_rx,
            detection_tx,
            analysis_interval_secs: beaconing.analysis_interval_secs,
        }
    }

    pub async fn run(mut self) {
        log!(DetectionLog::BeaconingDetectorStarted);
        let mut analysis_interval = interval(Duration::from_secs(self.analysis_interval_secs));
        loop {
            tokio::select! {
                result = self.alert_rx.recv() => {
                    match result {
                        Ok(alert) => self.state.record_flow(&alert),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = analysis_interval.tick() => {
                    for event in self.state.analyze() {
                        super::send_detection_or_log(&self.detection_tx, event);
                    }
                    self.state.cleanup();
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BeaconingKey {
    src_ip: String,
    dst_ip: String,
    protocol: u8,
    dst_port: u16,
}

struct CachedFlow {
    timestamps: Vec<Instant>,
    last_alerted: Option<Instant>,
}

pub struct BeaconingState {
    flow_cache: DashMap<BeaconingKey, CachedFlow>,
    min_observations: usize,
    cv_threshold: f64,
    max_cache_entries: usize,
    max_timestamps_per_flow: usize,
    expiry_secs: u64,
    alert_cooldown_secs: u64,
}

impl BeaconingState {
    pub fn new(
        min_observations: usize,
        cv_threshold: f64,
        max_cache_entries: usize,
        max_timestamps_per_flow: usize,
        expiry_secs: u64,
        alert_cooldown_secs: u64,
    ) -> Self {
        Self {
            flow_cache: DashMap::new(),
            min_observations,
            cv_threshold,
            max_cache_entries,
            max_timestamps_per_flow,
            expiry_secs,
            alert_cooldown_secs,
        }
    }

    pub fn record_flow(&self, alert: &FlowObservation) {
        let key = BeaconingKey {
            src_ip: alert.src_ip.clone(),
            dst_ip: alert.dst_ip.clone(),
            protocol: alert.protocol,
            dst_port: alert.dst_port,
        };
        let now = Instant::now();

        let mut entry = self.flow_cache.entry(key).or_insert_with(|| CachedFlow {
            timestamps: Vec::new(),
            last_alerted: None,
        });

        entry.timestamps.push(now);

        if entry.timestamps.len() > self.max_timestamps_per_flow {
            let excess = entry.timestamps.len() - self.max_timestamps_per_flow;
            entry.timestamps.drain(..excess);
        }
    }

    pub fn analyze(&self) -> Vec<DetectionEvent> {
        let now = Instant::now();
        let cooldown = Duration::from_secs(self.alert_cooldown_secs);

        let mut candidates: Vec<(BeaconingKey, f64, usize)> = Vec::new();
        for entry in self.flow_cache.iter() {
            let flow = entry.value();
            if flow.timestamps.len() < self.min_observations {
                continue;
            }
            if let Some(last) = flow.last_alerted
                && now.duration_since(last) < cooldown
            {
                continue;
            }
            let cv = compute_cv(&flow.timestamps);
            if cv < self.cv_threshold {
                candidates.push((entry.key().clone(), cv, flow.timestamps.len()));
            }
        }

        let mut events = Vec::new();
        for (key, cv, count) in candidates {
            log!(DetectionLog::BeaconingDetected(
                key.src_ip.clone(),
                key.dst_ip.clone(),
                key.dst_port,
                cv,
                count,
            ));

            events.push(DetectionEvent {
                source: DetectionSource::Beaconing,
                attack_type: CanonicalAttackType::C2Beacon.as_str().to_string(),
                confidence: (1.0 - cv / self.cv_threshold) as f32 * 0.5 + 0.5,
                source_ip: key.src_ip.clone(),
                dest_ip: key.dst_ip.clone(),
                protocol: key.protocol,
                packet_count: count as u64,
                flow_duration_us: 0,
                ae_score: 0.0,
                anomaly_score: 0.0,
                c2_score: 0.0,
            });

            if let Some(mut entry) = self.flow_cache.get_mut(&key) {
                entry.last_alerted = Some(now);
            }
        }

        events
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let expiry = Duration::from_secs(self.expiry_secs);

        self.flow_cache.retain(|_, flow| {
            flow.timestamps
                .last()
                .is_some_and(|last| now.duration_since(*last) < expiry)
        });

        if self.flow_cache.len() > self.max_cache_entries {
            let excess = self.flow_cache.len() - self.max_cache_entries;
            let keys_to_remove: Vec<BeaconingKey> =
                self.flow_cache.iter().take(excess).map(|e| e.key().clone()).collect();
            for key in keys_to_remove {
                self.flow_cache.remove(&key);
            }
        }
    }
}

pub fn compute_cv(timestamps: &[Instant]) -> f64 {
    if timestamps.len() < 2 {
        return f64::MAX;
    }

    let mut sum = 0.0;
    let mut sum_sq = 0.0;
    let mut count = 0;
    for window in timestamps.windows(2) {
        let interval = window[1].duration_since(window[0]).as_secs_f64();
        sum += interval;
        sum_sq += interval * interval;
        count += 1;
    }

    let n = count as f64;
    let mean = sum / n;

    if mean <= 0.0 {
        return f64::MAX;
    }
    let variance = ((sum_sq / n) - (mean * mean)).max(0.0);
    let std = variance.sqrt();

    std / mean
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::core::detection::beaconing::{BeaconingState, CachedFlow, compute_cv};
    use crate::domain::common::event::DetectionSource;
    use crate::domain::detection::attack_type::CanonicalAttackType;
    use crate::domain::detection::flow_observation::FlowObservation;

    fn test_key(protocol: u8, dst_port: u16) -> super::BeaconingKey {
        super::BeaconingKey {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.2.3.4".to_string(),
            protocol,
            dst_port,
        }
    }

    #[test]
    fn cv_perfectly_periodic() {
        let base = Instant::now();
        let timestamps: Vec<Instant> = (0..10).map(|i| base + Duration::from_secs(i * 60)).collect();
        let cv = compute_cv(&timestamps);
        assert!(cv < 0.01, "Perfectly periodic CV should be ~0, got {cv}");
    }

    #[test]
    fn cv_random_high() {
        let base = Instant::now();
        let timestamps = vec![
            base,
            base + Duration::from_secs(1),
            base + Duration::from_secs(100),
            base + Duration::from_secs(101),
            base + Duration::from_secs(500),
            base + Duration::from_secs(501),
        ];
        let cv = compute_cv(&timestamps);
        assert!(cv > 0.5, "Random intervals CV should be high, got {cv}");
    }

    #[test]
    fn cv_with_slight_jitter() {
        let base = Instant::now();
        let timestamps = vec![
            base,
            base + Duration::from_millis(60_000),
            base + Duration::from_millis(121_000),
            base + Duration::from_millis(179_000),
            base + Duration::from_millis(240_000),
            base + Duration::from_millis(299_000),
        ];
        let cv = compute_cv(&timestamps);
        assert!(cv < 0.3, "Slight jitter CV should be < 0.3, got {cv}");
    }

    #[test]
    fn cv_insufficient_data() {
        let base = Instant::now();
        assert_eq!(compute_cv(&[base]), f64::MAX);
        assert_eq!(compute_cv(&[]), f64::MAX);
    }

    #[test]
    fn beaconing_state_detects_periodic_flows() {
        let state = BeaconingState::new(5, 0.3, 50_000, 100, 3600, 120);
        let base = Instant::now();
        let key = test_key(6, 443);
        state.flow_cache.insert(
            key,
            CachedFlow {
                timestamps: (0..10).map(|i| base + Duration::from_secs(i * 60)).collect(),
                last_alerted: None,
            },
        );
        let events = state.analyze();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, DetectionSource::Beaconing);
        assert_eq!(events[0].attack_type, CanonicalAttackType::C2Beacon.as_str());
        assert_eq!(events[0].protocol, 6);
    }

    #[test]
    fn record_flow_respects_configured_timestamp_cap() {
        let state = BeaconingState::new(1, 0.3, 50_000, 3, 3600, 120);
        let alert = FlowObservation {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.2.3.4".to_string(),
            dst_port: 443,
            protocol: 6,
            packet_count: 10,
            flow_duration_us: 1000,
        };

        for _ in 0..5 {
            state.record_flow(&alert);
        }

        let key = test_key(6, 443);
        assert_eq!(state.flow_cache.get(&key).unwrap().timestamps.len(), 3);
    }

    #[test]
    fn beaconing_state_keeps_protocols_separate_and_emits_observed_protocol() {
        let state = BeaconingState::new(3, 0.3, 50_000, 100, 3600, 120);
        let base = Instant::now();
        state.flow_cache.insert(
            test_key(17, 53),
            CachedFlow {
                timestamps: (0..3).map(|i| base + Duration::from_secs(i * 60)).collect(),
                last_alerted: None,
            },
        );
        state.flow_cache.insert(
            test_key(6, 53),
            CachedFlow {
                timestamps: vec![base],
                last_alerted: None,
            },
        );

        let events = state.analyze();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].protocol, 17);
        assert_eq!(events[0].source_ip, "10.0.0.1");
        assert_eq!(events[0].dest_ip, "1.2.3.4");
    }
}
