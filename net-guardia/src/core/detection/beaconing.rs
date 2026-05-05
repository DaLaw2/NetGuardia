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
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;

pub struct BeaconingDetector {
    state: BeaconingState,
    alert_rx: broadcast::Receiver<AlertMessage>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    analysis_interval_secs: u64,
}

impl BeaconingDetector {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        alert_rx: broadcast::Receiver<AlertMessage>,
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

    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
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
                        if let Err(mpsc::error::TrySendError::Full(d)) = self.detection_tx.try_send(event) {
                            log!(DetectionLog::DetectionChannelDrop(
                                format!("{:?}", d.source),
                                d.attack_type,
                                d.source_ip,
                            ));
                        }
                    }
                    self.state.cleanup();
                }
            }
        }
    }
}

type FlowTuple = (String, String, u16);

struct CachedFlow {
    timestamps: Vec<Instant>,
    last_alerted: Option<Instant>,
}

pub struct BeaconingState {
    flow_cache: DashMap<FlowTuple, CachedFlow>,
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

    pub fn record_flow(&self, alert: &AlertMessage) {
        let key = (alert.src_ip.clone(), alert.dst_ip.clone(), alert.dst_port);
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

        let mut candidates: Vec<(FlowTuple, f64, usize)> = Vec::new();
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
            let (src_ip, dst_ip, dst_port) = &key;
            log!(DetectionLog::BeaconingDetected(
                src_ip.clone(),
                dst_ip.clone(),
                *dst_port,
                cv,
                count,
            ));

            events.push(DetectionEvent {
                source: DetectionSource::Beaconing,
                attack_type: CanonicalAttackType::C2Beacon.as_str().to_string(),
                confidence: (1.0 - cv / self.cv_threshold) as f32 * 0.5 + 0.5,
                source_ip: src_ip.clone(),
                dest_ip: dst_ip.clone(),
                protocol: 6,
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
            let keys_to_remove: Vec<FlowTuple> = self.flow_cache.iter().take(excess).map(|e| e.key().clone()).collect();
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

    let intervals: Vec<f64> = timestamps
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_secs_f64())
        .collect();

    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;

    if mean <= 0.0 {
        return f64::MAX;
    }

    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std = variance.sqrt();

    std / mean
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::core::detection::beaconing::{BeaconingState, CachedFlow, compute_cv};
    use crate::domain::common::event::DetectionSource;
    use crate::domain::detection::attack_type::CanonicalAttackType;
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
        let key = ("10.0.0.1".to_string(), "1.2.3.4".to_string(), 443_u16);
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
    }

    #[test]
    fn record_flow_respects_configured_timestamp_cap() {
        let state = BeaconingState::new(1, 0.3, 50_000, 3, 3600, 120);
        let alert = crate::domain::detection::ml_detection::AlertMessage {
            timestamp: 0,
            flow_key: "10.0.0.1:12345-1.2.3.4:443".to_string(),
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "1.2.3.4".to_string(),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_attack: true,
            attack_type: Some("c2_beacon".to_string()),
            confidence: 0.9,
            packet_count: 10,
            flow_duration_us: 1000,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        for _ in 0..5 {
            state.record_flow(&alert);
        }

        let key = ("10.0.0.1".to_string(), "1.2.3.4".to_string(), 443_u16);
        assert_eq!(state.flow_cache.get(&key).unwrap().timestamps.len(), 3);
    }
}
