use std::collections::HashSet;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;

use crate::core::correlation::correlation_cleanup::capped_cleanup;
use crate::domain::common::config::correlation::CorrelationDetectorParams;
use crate::domain::common::event::{DetectionEvent, DetectionSource};
use crate::domain::detection::attack_type::CanonicalAttackType;
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::log::DetectionLog;

struct TimedSourceSet {
    sources: HashSet<String>,
    window_start: Instant,
    last_alerted: Option<Instant>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BotnetKey {
    dst_ip: String,
    protocol: u8,
    dst_port: u16,
}

pub struct BotnetDetector {
    state: DashMap<BotnetKey, TimedSourceSet>,
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

    pub fn process(&self, alert: &FlowObservation) -> Option<DetectionEvent> {
        let key = botnet_key(alert);
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedSourceSet {
                sources: HashSet::new(),
                window_start: now,
                last_alerted: None,
            });

            let set = entry.value_mut();

            if now.duration_since(set.window_start) >= self.window {
                set.sources.clear();
                set.window_start = now;
            }

            set.sources.insert(alert.src_ip.clone());

            if set.sources.len() >= self.threshold {
                if let Some(last) = set.last_alerted
                    && now.duration_since(last) < self.window
                {
                    set.sources.clear();
                    set.window_start = now;
                    None
                } else {
                    Some(set.sources.len())
                }
            } else {
                None
            }
        };

        if let Some(unique_sources) = should_alert {
            log!(DetectionLog::BotnetDetected(
                format!("{}:{}", alert.dst_ip, alert.dst_port),
                unique_sources,
                self.window_secs,
            ));

            let attacker_ip = alert.src_ip.clone();
            let victim_ip = alert.dst_ip.clone();
            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: CanonicalAttackType::BotActivity.as_str().to_string(),
                confidence: 0.85,
                source_ip: attacker_ip,
                dest_ip: victim_ip,
                protocol: alert.protocol,
                packet_count: alert.packet_count,
                flow_duration_us: alert.flow_duration_us,
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

fn botnet_key(alert: &FlowObservation) -> BotnetKey {
    BotnetKey {
        dst_ip: alert.dst_ip.clone(),
        protocol: alert.protocol,
        dst_port: alert.dst_port,
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    fn make_alert(src_ip: &str, dst_ip: &str) -> FlowObservation {
        make_alert_to_port(src_ip, dst_ip, 80)
    }

    fn make_alert_to_port(src_ip: &str, dst_ip: &str, dst_port: u16) -> FlowObservation {
        FlowObservation {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol: 6,
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
        assert_eq!(event.source_ip, "10.0.0.9");
        assert_eq!(event.dest_ip, "192.168.1.1");
    }

    #[test]
    fn botnet_threshold_is_scoped_to_destination_port() {
        let detector = BotnetDetector::new(
            &CorrelationDetectorParams {
                window_secs: 300,
                threshold: 3,
            },
            10_000,
        );

        assert!(
            detector
                .process(&make_alert_to_port("10.0.0.1", "192.168.1.1", 80))
                .is_none()
        );
        assert!(
            detector
                .process(&make_alert_to_port("10.0.0.2", "192.168.1.1", 80))
                .is_none()
        );
        assert!(
            detector
                .process(&make_alert_to_port("10.0.0.3", "192.168.1.1", 443))
                .is_none()
        );

        let event = detector
            .process(&make_alert_to_port("10.0.0.4", "192.168.1.1", 80))
            .expect("third source on the same destination port should alert");

        assert_eq!(event.source_ip, "10.0.0.4");
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
