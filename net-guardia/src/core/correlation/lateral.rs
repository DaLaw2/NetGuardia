use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;

use crate::common::utils::ip_address::is_internal_ip;
use crate::core::correlation::correlation_cleanup::capped_cleanup;
use crate::domain::common::config::correlation::CorrelationDetectorParams;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::attack_type::CanonicalAttackType;
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::log::DetectionLog;

struct TimedDestSet {
    dests: HashSet<String>,
    window_start: Instant,
    last_alerted: Option<Instant>,
}

pub struct LateralMovementDetector {
    state: DashMap<String, TimedDestSet>,
    window: Duration,
    window_secs: u64,
    threshold: usize,
    max_tracked: usize,
}

impl LateralMovementDetector {
    pub fn new(params: &CorrelationDetectorParams, max_tracked: usize) -> Self {
        Self {
            state: DashMap::new(),
            window: Duration::from_secs(params.window_secs),
            window_secs: params.window_secs,
            threshold: params.threshold,
            max_tracked,
        }
    }

    pub fn process(&self, alert: &FlowObservation) -> Option<DetectionEvent> {
        if !is_internal_ip(&alert.src_ip) || !is_internal_ip(&alert.dst_ip) {
            return None;
        }

        let key = alert.src_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedDestSet {
                dests: HashSet::new(),
                window_start: now,
                last_alerted: None,
            });

            let set = entry.value_mut();

            if now.duration_since(set.window_start) >= self.window {
                set.dests.clear();
                set.window_start = now;
            }

            set.dests.insert(alert.dst_ip.clone());

            if set.dests.len() >= self.threshold {
                if let Some(last) = set.last_alerted
                    && now.duration_since(last) < self.window
                {
                    set.dests.clear();
                    set.window_start = now;
                    return None;
                }
                Some(set.dests.len())
            } else {
                None
            }
        };

        if let Some(unique_dests) = should_alert {
            log!(DetectionLog::LateralMovementDetected(
                key.clone(),
                unique_dests,
                self.window_secs,
            ));

            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: CanonicalAttackType::LateralMovement.as_str().to_string(),
                confidence: 0.75,
                source_ip: key.clone(),
                dest_ip: alert.dst_ip.clone(),
                protocol: alert.protocol,
                packet_count: alert.packet_count,
                flow_duration_us: alert.flow_duration_us,
                ae_score: 0.0,
                anomaly_score: 0.0,
                c2_score: 0.0,
            };

            if let Some(mut entry) = self.state.get_mut(&key) {
                entry.dests.clear();
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
    use crate::common::utils::ip_address::is_internal_ip;

    #[test]
    fn test_internal_ip_detection() {
        assert!(is_internal_ip("10.0.0.1"));
        assert!(is_internal_ip("10.255.255.255"));
        assert!(is_internal_ip("172.16.0.1"));
        assert!(is_internal_ip("172.31.255.255"));
        assert!(is_internal_ip("192.168.0.1"));
        assert!(is_internal_ip("192.168.255.255"));
        assert!(is_internal_ip("127.0.0.1"));

        assert!(!is_internal_ip("8.8.8.8"));
        assert!(!is_internal_ip("172.32.0.1"));
        assert!(!is_internal_ip("192.169.0.1"));
        assert!(!is_internal_ip("1.1.1.1"));
    }

    #[test]
    fn test_internal_ipv6() {
        assert!(is_internal_ip("fc00::1"));
        assert!(is_internal_ip("fd12:3456:789a::1"));
        assert!(is_internal_ip("::1"));

        assert!(!is_internal_ip("2001:db8::1"));
        assert!(!is_internal_ip("2607:f8b0::1"));
    }

    #[test]
    fn test_invalid_ip() {
        assert!(!is_internal_ip("not-an-ip"));
        assert!(!is_internal_ip(""));
    }

    fn make_alert(src_ip: &str, dst_ip: &str) -> FlowObservation {
        FlowObservation {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port: 445,
            protocol: 6,
            packet_count: 50,
            flow_duration_us: 500_000,
        }
    }

    fn test_params() -> CorrelationDetectorParams {
        CorrelationDetectorParams {
            window_secs: 300,
            threshold: 5,
        }
    }

    #[test]
    fn lateral_threshold_triggers_for_internal_only() {
        let detector = LateralMovementDetector::new(&test_params(), 10_000);

        assert!(detector.process(&make_alert("10.0.0.1", "8.8.8.8")).is_none());

        for i in 1..5 {
            assert!(
                detector
                    .process(&make_alert("10.0.0.1", &format!("10.0.1.{i}")))
                    .is_none(),
                "Should not alert below threshold"
            );
        }

        let event = detector
            .process(&make_alert("10.0.0.1", "10.0.1.5"))
            .expect("Should alert at threshold");
        assert_eq!(event.source, DetectionSource::Correlation);
    }
}
