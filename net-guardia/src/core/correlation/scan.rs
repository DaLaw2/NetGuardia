use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;
use tokio::sync::mpsc;

use crate::model::detection::ml_detection::AlertMessage;
use crate::model::event::{DetectionEvent, DetectionSource};
use crate::model::log::detection::DetectionLog;

/// Window within which unique destination ports are counted per source.
const SCAN_WINDOW_SECS: u64 = 120; // 2 minutes

/// Minimum unique destination ports to trigger a scan alert.
const SCAN_THRESHOLD: usize = 20;

/// Maximum tracked source IPs to bound memory.
const MAX_TRACKED_SRCS: usize = 10_000;

struct TimedPortSet {
    ports: HashSet<u16>,
    window_start: Instant,
    last_dst_ip: String,
}

/// Detects port scanning: a single source IP probing many destination ports.
pub struct ScanDetector {
    /// src_ip → set of unique dst_ports within the time window
    state: DashMap<String, TimedPortSet>,
    window: Duration,
    threshold: usize,
}

impl ScanDetector {
    pub fn new() -> Self {
        Self {
            state: DashMap::new(),
            window: Duration::from_secs(SCAN_WINDOW_SECS),
            threshold: SCAN_THRESHOLD,
        }
    }

    /// Process an alert and emit a DetectionEvent if the scan threshold is crossed.
    pub fn process(&self, alert: &AlertMessage, detection_tx: &mpsc::Sender<DetectionEvent>) {
        let key = alert.src_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedPortSet {
                ports: HashSet::new(),
                window_start: now,
                last_dst_ip: alert.dst_ip.clone(),
            });

            let set = entry.value_mut();

            // Reset window if expired
            if now.duration_since(set.window_start) >= self.window {
                set.ports.clear();
                set.window_start = now;
            }

            set.ports.insert(alert.dst_port);
            set.last_dst_ip = alert.dst_ip.clone();

            if set.ports.len() >= self.threshold {
                Some((set.ports.len(), set.last_dst_ip.clone()))
            } else {
                None
            }
        };

        if let Some((unique_ports, last_dst_ip)) = should_alert {
            log!(DetectionLog::ScanDetected(key.clone(), unique_ports, SCAN_WINDOW_SECS,));

            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: "port_scan".to_string(),
                confidence: 0.80,
                source_ip: key.clone(),
                dest_ip: last_dst_ip,
                protocol: alert.protocol,
                packet_count: 0,
                flow_duration_us: 0,
                ae_score: 0.0,
                anomaly_score: 0.0,
                c2_score: 0.0,
            };

            let _ = detection_tx.try_send(event);

            // Reset after alerting
            if let Some(mut entry) = self.state.get_mut(&key) {
                entry.ports.clear();
                entry.window_start = now;
            }
        }
    }

    /// Remove expired entries. Returns number of entries removed.
    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let window = self.window;
        let before = self.state.len();

        self.state
            .retain(|_, set| now.duration_since(set.window_start) < window);

        if self.state.len() > MAX_TRACKED_SRCS {
            let excess = self.state.len() - MAX_TRACKED_SRCS;
            let keys_to_remove: Vec<String> = self.state.iter().take(excess).map(|e| e.key().clone()).collect();
            for key in keys_to_remove {
                self.state.remove(&key);
            }
        }

        before.saturating_sub(self.state.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_alert(src_ip: &str, dst_port: u16) -> AlertMessage {
        AlertMessage {
            timestamp: 0,
            flow_key: String::new(),
            src_ip: src_ip.to_string(),
            dst_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            dst_port,
            protocol: 6,
            is_attack: true,
            attack_type: Some("Reconnaissance".to_string()),
            confidence: 0.7,
            ae_score: 0.3,
            anomaly_score: 0.0,
            c2_score: 0.0,
            packet_count: 5,
            flow_duration_us: 100_000,
        }
    }

    #[tokio::test]
    async fn scan_threshold_triggers_alert() {
        let detector = ScanDetector::new();
        let (tx, mut rx) = mpsc::channel(64);

        for port in 0..19 {
            let alert = make_alert("10.0.0.1", port);
            detector.process(&alert, &tx);
        }
        assert!(rx.try_recv().is_err(), "Should not alert below threshold");

        let alert = make_alert("10.0.0.1", 19);
        detector.process(&alert, &tx);
        let event = rx.try_recv().expect("Should alert at threshold");
        assert_eq!(event.attack_type, "port_scan");
    }

    #[tokio::test]
    async fn different_sources_tracked_independently() {
        let detector = ScanDetector::new();
        let (tx, mut rx) = mpsc::channel(64);

        for port in 0..15 {
            detector.process(&make_alert("10.0.0.1", port), &tx);
            detector.process(&make_alert("10.0.0.2", port), &tx);
        }
        assert!(rx.try_recv().is_err(), "Neither should alert at 15 ports");
    }
}
