use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;

use crate::core::correlation::correlation_cleanup::capped_cleanup;
use crate::domain::common::config::correlation::CorrelationDetectorParams;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::attack_type::CanonicalAttackType;
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;

struct TimedSourceSet {
    sources: HashSet<String>,
    window_start: Instant,
    last_alert: AlertMessage,
    last_alerted: Option<Instant>,
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

    pub fn process(&self, alert: &AlertMessage) -> Option<DetectionEvent> {
        let key = alert.dst_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedSourceSet {
                sources: HashSet::new(),
                window_start: now,
                last_alert: alert.clone(),
                last_alerted: None,
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
                if let Some(last) = set.last_alerted
                    && now.duration_since(last) < self.window
                {
                    set.sources.clear();
                    set.window_start = now;
                    return None;
                }
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
                attack_type: CanonicalAttackType::BotActivity.as_str().to_string(),
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

            if let Some(mut entry) = self.state.get_mut(&key) {
                entry.sources.clear();
                entry.window_start = now;
                entry.last_alerted = Some(now);
            }

            return Some(event);
        }

        None
    }

    pub fn cleanup(&self) -> usize {
        capped_cleanup(&self.state, self.window, self.max_tracked, |s| s.window_start)
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

    #[test]
    fn botnet_threshold_triggers_alert() {
        let detector = BotnetDetector::new(&test_params(), 10_000);

        for i in 0..9 {
            let alert = make_alert(&format!("10.0.0.{i}"), "192.168.1.1");
            assert!(detector.process(&alert).is_none(), "Should not alert below threshold");
        }

        let alert = make_alert("10.0.0.9", "192.168.1.1");
        let event = detector.process(&alert).expect("Should alert at threshold");
        assert_eq!(event.source, DetectionSource::Correlation);
        // source_ip must be the attacker, NOT the victim
        assert_eq!(event.source_ip, "10.0.0.9");
        assert_eq!(event.dest_ip, "192.168.1.1");
    }

    #[test]
    fn cleanup_removes_expired() {
        let detector = BotnetDetector {
            state: DashMap::new(),
            window: Duration::from_millis(10),
            window_secs: 0,
            threshold: 10,
            max_tracked: 10_000,
        };

        let alert = make_alert("10.0.0.1", "192.168.1.1");
        detector.process(&alert);
        assert_eq!(detector.state.len(), 1);

        thread::sleep(Duration::from_millis(20));
        let removed = detector.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(detector.state.len(), 0);
    }
}
