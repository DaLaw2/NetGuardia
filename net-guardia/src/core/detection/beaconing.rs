use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use crate::model::detection::ml_detection::AlertMessage;
use crate::model::event::{DetectionEvent, DetectionSource};
use crate::model::log::detection::DetectionLog;

/// How often to analyze cached flows for beaconing patterns.
const ANALYSIS_INTERVAL_SECS: u64 = 30;

/// Minimum number of flow observations before computing CV.
const MIN_OBSERVATIONS: usize = 5;

/// CV threshold: values below this indicate periodic (beaconing) behavior.
/// 0 = perfectly periodic, 1 = random. C2 beacons typically have CV < 0.3.
const CV_THRESHOLD: f64 = 0.3;

/// Maximum entries in the flow cache to bound memory.
const MAX_CACHE_ENTRIES: usize = 50_000;

/// Expire entries not seen within this window.
const EXPIRY_SECS: u64 = 600; // 10 minutes

/// Cooldown between re-alerting on the same (src, dst, port) tuple.
const ALERT_COOLDOWN_SECS: u64 = 300; // 5 minutes

/// Key for tracking flow timing: (src_ip, dst_ip, dst_port).
type FlowTuple = (String, String, u16);

struct CachedFlow {
    timestamps: Vec<Instant>,
    last_alerted: Option<Instant>,
}

/// Detects C2 beaconing by analyzing the periodicity of flows between
/// (src_ip, dst_ip, dst_port) tuples. Uses coefficient of variation (CV)
/// of inter-arrival times: CV < 0.3 with sufficient observations = beaconing.
pub struct BeaconingDetector {
    flow_cache: DashMap<FlowTuple, CachedFlow>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    alert_rx: broadcast::Receiver<AlertMessage>,
}

impl BeaconingDetector {
    pub fn new(alert_rx: broadcast::Receiver<AlertMessage>, detection_tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self {
            flow_cache: DashMap::new(),
            detection_tx,
            alert_rx,
        }
    }

    /// Spawn the beaconing detector as a background task.
    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::BeaconingDetectorStarted);

        let mut analysis_interval = interval(Duration::from_secs(ANALYSIS_INTERVAL_SECS));

        loop {
            tokio::select! {
                result = self.alert_rx.recv() => {
                    match result {
                        Ok(alert) => self.record_flow(&alert),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = analysis_interval.tick() => {
                    self.analyze_and_alert();
                    self.cleanup();
                }
            }
        }
    }

    fn record_flow(&self, alert: &AlertMessage) {
        let key = (alert.src_ip.clone(), alert.dst_ip.clone(), alert.dst_port);
        let now = Instant::now();

        let mut entry = self.flow_cache.entry(key).or_insert_with(|| CachedFlow {
            timestamps: Vec::new(),
            last_alerted: None,
        });

        entry.timestamps.push(now);

        // Cap stored timestamps to avoid unbounded growth per entry
        if entry.timestamps.len() > 100 {
            let excess = entry.timestamps.len() - 100;
            entry.timestamps.drain(..excess);
        }
    }

    fn analyze_and_alert(&self) {
        let now = Instant::now();
        let cooldown = Duration::from_secs(ALERT_COOLDOWN_SECS);

        // Phase 1: read-lock scan to find beaconing candidates (avoids holding write locks
        // across the entire 50K-entry iteration, reducing contention with record_flow).
        let mut alerts: Vec<(FlowTuple, f64, usize)> = Vec::new();
        for entry in self.flow_cache.iter() {
            let flow = entry.value();
            if flow.timestamps.len() < MIN_OBSERVATIONS {
                continue;
            }
            if let Some(last) = flow.last_alerted
                && now.duration_since(last) < cooldown
            {
                continue;
            }
            let cv = compute_cv(&flow.timestamps);
            if cv < CV_THRESHOLD {
                alerts.push((entry.key().clone(), cv, flow.timestamps.len()));
            }
        }

        // Phase 2: selective write-lock only for entries that need last_alerted update.
        for (key, cv, count) in alerts {
            let (src_ip, dst_ip, dst_port) = &key;
            log!(DetectionLog::BeaconingDetected(
                src_ip.clone(),
                dst_ip.clone(),
                *dst_port,
                cv,
                count,
            ));

            let event = DetectionEvent {
                source: DetectionSource::Beaconing,
                attack_type: "c2_communication".to_string(),
                confidence: (1.0 - cv / CV_THRESHOLD) as f32 * 0.5 + 0.5,
                source_ip: src_ip.clone(),
                dest_ip: dst_ip.clone(),
                protocol: 6,
                packet_count: count as u64,
                flow_duration_us: 0,
                ae_score: 0.0,
                anomaly_score: 0.0,
                c2_score: 0.0,
            };

            let _ = self.detection_tx.try_send(event);
            if let Some(mut entry) = self.flow_cache.get_mut(&key) {
                entry.last_alerted = Some(now);
            }
        }
    }

    fn cleanup(&self) {
        let now = Instant::now();
        let expiry = Duration::from_secs(EXPIRY_SECS);

        self.flow_cache.retain(|_, flow| {
            flow.timestamps
                .last()
                .is_some_and(|last| now.duration_since(*last) < expiry)
        });

        // Enforce max capacity
        if self.flow_cache.len() > MAX_CACHE_ENTRIES {
            let excess = self.flow_cache.len() - MAX_CACHE_ENTRIES;
            let keys_to_remove: Vec<FlowTuple> = self.flow_cache.iter().take(excess).map(|e| e.key().clone()).collect();
            for key in keys_to_remove {
                self.flow_cache.remove(&key);
            }
        }
    }
}

/// Compute the coefficient of variation (std / mean) of inter-arrival times.
/// Returns f64::MAX if fewer than 2 timestamps (no intervals to compute).
fn compute_cv(timestamps: &[Instant]) -> f64 {
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
        // Perfectly periodic: CV should be ~0
        let base = Instant::now();
        let timestamps: Vec<Instant> = (0..10).map(|i| base + Duration::from_secs(i * 60)).collect();
        let cv = compute_cv(&timestamps);
        assert!(cv < 0.01, "Perfectly periodic CV should be ~0, got {cv}");
    }

    #[test]
    fn cv_random_high() {
        // Irregular intervals: CV should be high
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
        // Periodic with small jitter: CV should be low but > 0
        let base = Instant::now();
        let timestamps = vec![
            base,
            base + Duration::from_millis(60_000),
            base + Duration::from_millis(121_000), // 61s interval
            base + Duration::from_millis(179_000), // 58s interval
            base + Duration::from_millis(240_000), // 61s interval
            base + Duration::from_millis(299_000), // 59s interval
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

    #[tokio::test]
    async fn beaconing_detector_records_and_detects() {
        let (alert_tx, alert_rx) = broadcast::channel(64);
        let (detection_tx, mut detection_rx) = mpsc::channel(64);

        let detector = BeaconingDetector::new(alert_rx, detection_tx);

        // Manually record periodic flows
        let base = Instant::now();
        let key = ("10.0.0.1".to_string(), "1.2.3.4".to_string(), 443_u16);
        detector.flow_cache.insert(
            key,
            CachedFlow {
                timestamps: (0..10).map(|i| base + Duration::from_secs(i * 60)).collect(),
                last_alerted: None,
            },
        );

        detector.analyze_and_alert();

        let event = detection_rx.try_recv().expect("Should detect beaconing");
        assert_eq!(event.source, DetectionSource::Beaconing);
        assert_eq!(event.attack_type, "c2_communication");

        drop(alert_tx);
    }
}
