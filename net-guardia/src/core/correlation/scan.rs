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

struct TimedPortSet {
    ports: HashSet<u16>,
    window_start: Instant,
    last_dst_ip: String,
    last_alerted: Option<Instant>,
}

/// Detects port scanning: a single source IP probing many destination ports.
pub struct ScanDetector {
    /// src_ip → set of unique dst_ports within the time window
    state: DashMap<String, TimedPortSet>,
    window: Duration,
    window_secs: u64,
    threshold: usize,
    max_tracked: usize,
}

impl ScanDetector {
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
        let key = alert.src_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedPortSet {
                ports: HashSet::new(),
                window_start: now,
                last_dst_ip: alert.dst_ip.clone(),
                last_alerted: None,
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
                if let Some(last) = set.last_alerted
                    && now.duration_since(last) < self.window
                {
                    set.ports.clear();
                    set.window_start = now;
                    return None;
                }
                Some((set.ports.len(), set.last_dst_ip.clone()))
            } else {
                None
            }
        };

        if let Some((unique_ports, last_dst_ip)) = should_alert {
            log!(DetectionLog::ScanDetected(key.clone(), unique_ports, self.window_secs,));

            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: CanonicalAttackType::PortScan.as_str().to_string(),
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

            if let Some(mut entry) = self.state.get_mut(&key) {
                entry.ports.clear();
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
    use super::*;

    fn test_params() -> CorrelationDetectorParams {
        CorrelationDetectorParams {
            window_secs: 120,
            threshold: 20,
        }
    }

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

    #[test]
    fn scan_threshold_triggers_alert() {
        let detector = ScanDetector::new(&test_params(), 10_000);

        for port in 0..19 {
            let alert = make_alert("10.0.0.1", port);
            assert!(detector.process(&alert).is_none());
        }

        let alert = make_alert("10.0.0.1", 19);
        let event = detector.process(&alert).expect("Should alert at threshold");
        assert_eq!(event.attack_type, "port_scan");
    }

    #[test]
    fn different_sources_tracked_independently() {
        let detector = ScanDetector::new(&test_params(), 10_000);

        for port in 0..15 {
            assert!(detector.process(&make_alert("10.0.0.1", port)).is_none());
            assert!(detector.process(&make_alert("10.0.0.2", port)).is_none());
        }
    }
}
