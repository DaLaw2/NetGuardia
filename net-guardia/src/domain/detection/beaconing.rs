use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;

use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;

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
    expiry_secs: u64,
    alert_cooldown_secs: u64,
}

impl BeaconingState {
    pub fn new(
        min_observations: usize,
        cv_threshold: f64,
        max_cache_entries: usize,
        expiry_secs: u64,
        alert_cooldown_secs: u64,
    ) -> Self {
        Self {
            flow_cache: DashMap::new(),
            min_observations,
            cv_threshold,
            max_cache_entries,
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

        if entry.timestamps.len() > 100 {
            let excess = entry.timestamps.len() - 100;
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
                attack_type: "c2_communication".to_string(),
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
    use super::*;

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
        let state = BeaconingState::new(5, 0.3, 50_000, 3600, 120);
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
        assert_eq!(events[0].attack_type, "c2_communication");
    }
}
