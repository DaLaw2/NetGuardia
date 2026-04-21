use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;
use tokio::sync::mpsc;

use crate::model::config::correlation::CorrelationDetectorParams;
use crate::model::detection::ml_detection::AlertMessage;
use crate::model::event::{DetectionEvent, DetectionSource};
use crate::model::log::detection::DetectionLog;

struct TimedSourceSet {
    sources: HashSet<String>,
    window_start: Instant,
    /// Most recent alert to this destination (used for protocol/confidence in DetectionEvent).
    last_alert: AlertMessage,
}

/// Detects coordinated attacks: multiple source IPs targeting the same destination IP:port.
/// Uses a DashMap for lock-free concurrent access.
pub struct BotnetDetector {
    /// dst_ip → set of unique src_ips within the time window
    state: DashMap<String, TimedSourceSet>,
    window: Duration,
    window_secs: u64,
    threshold: usize,
    max_tracked: usize,
}

impl BotnetDetector {
    pub fn new(params: &CorrelationDetectorParams, max_tracked: usize) -> Self {
        Self {
            state: DashMap::new(),
            window: Duration::from_secs(params.window_secs),
            window_secs: params.window_secs,
            threshold: params.threshold,
            max_tracked,
        }
    }

    /// Process an alert and return a DetectionEvent if the botnet threshold is crossed.
    pub fn process(&self, alert: &AlertMessage, detection_tx: &mpsc::Sender<DetectionEvent>) {
        let key = alert.dst_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedSourceSet {
                sources: HashSet::new(),
                window_start: now,
                last_alert: alert.clone(),
            });

            let set = entry.value_mut();

            // Reset window if expired
            if now.duration_since(set.window_start) >= self.window {
                set.sources.clear();
                set.window_start = now;
            }

            set.sources.insert(alert.src_ip.clone());
            set.last_alert = alert.clone();

            if set.sources.len() >= self.threshold {
                Some(set.sources.len())
            } else {
                None
            }
        };

        if let Some(unique_sources) = should_alert {
            log!(DetectionLog::BotnetDetected(
                key.clone(),
                unique_sources,
                self.window_secs,
            ));

            // source_ip = the latest attacker; dest_ip = the victim being targeted.
            // SOAR blocks source_ip, so we must NOT put the victim here.
            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: "threat_detected".to_string(),
                confidence: 0.85,
                source_ip: alert.src_ip.clone(),
                dest_ip: key.clone(),
                protocol: alert.protocol,
                packet_count: 0,
                flow_duration_us: 0,
                ae_score: 0.0,
                anomaly_score: 0.0,
                c2_score: 0.0,
            };

            let _ = detection_tx.try_send(event);

            // Reset after alerting to avoid repeated alerts within same window
            if let Some(mut entry) = self.state.get_mut(&key) {
                entry.sources.clear();
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

        // Enforce max capacity by removing oldest entries if over limit
        if self.state.len() > self.max_tracked {
            let excess = self.state.len() - self.max_tracked;
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
    use std::thread;

    use super::*;

    fn make_alert(src_ip: &str, dst_ip: &str) -> AlertMessage {
        AlertMessage {
            timestamp: 0,
            flow_key: String::new(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_attack: true,
            attack_type: Some("DDoS".to_string()),
            confidence: 0.9,
            ae_score: 0.5,
            anomaly_score: 0.0,
            c2_score: 0.0,
            packet_count: 100,
            flow_duration_us: 1_000_000,
        }
    }

    fn test_params() -> CorrelationDetectorParams {
        CorrelationDetectorParams {
            window_secs: 300,
            threshold: 10,
        }
    }

    #[tokio::test]
    async fn botnet_threshold_triggers_alert() {
        let detector = BotnetDetector::new(&test_params(), 10_000);
        let (tx, mut rx) = mpsc::channel(64);

        // Send alerts from 9 different sources (below threshold)
        for i in 0..9 {
            let alert = make_alert(&format!("10.0.0.{i}"), "192.168.1.1");
            detector.process(&alert, &tx);
        }
        assert!(rx.try_recv().is_err(), "Should not alert below threshold");

        // 10th source should trigger
        let alert = make_alert("10.0.0.9", "192.168.1.1");
        detector.process(&alert, &tx);
        let event = rx.try_recv().expect("Should alert at threshold");
        assert_eq!(event.source, DetectionSource::Correlation);
        // source_ip must be the attacker, NOT the victim
        assert_eq!(event.source_ip, "10.0.0.9");
        assert_eq!(event.dest_ip, "192.168.1.1");
    }

    #[tokio::test]
    async fn cleanup_removes_expired() {
        let detector = BotnetDetector {
            state: DashMap::new(),
            window: Duration::from_millis(10),
            window_secs: 0,
            threshold: 10,
            max_tracked: 10_000,
        };
        let (tx, _rx) = mpsc::channel(64);

        let alert = make_alert("10.0.0.1", "192.168.1.1");
        detector.process(&alert, &tx);
        assert_eq!(detector.state.len(), 1);

        thread::sleep(Duration::from_millis(20));
        let removed = detector.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(detector.state.len(), 0);
    }
}
