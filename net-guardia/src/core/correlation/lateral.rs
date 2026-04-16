use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use macros::log;
use tokio::sync::mpsc;

use crate::model::detection::ml_detection::AlertMessage;
use crate::model::event::{DetectionEvent, DetectionSource};
use crate::model::log::detection::DetectionLog;

/// Window within which unique internal destinations are counted per source.
const LATERAL_WINDOW_SECS: u64 = 300; // 5 minutes

/// Minimum unique internal destination IPs to trigger a lateral movement alert.
const LATERAL_THRESHOLD: usize = 5;

/// Maximum tracked source IPs to bound memory.
const MAX_TRACKED_SRCS: usize = 10_000;

struct TimedDestSet {
    dests: HashSet<String>,
    window_start: Instant,
}

/// Detects lateral movement: an internal IP reaching many other internal IPs.
pub struct LateralMovementDetector {
    /// src_ip → set of unique internal dst_ips within the time window
    state: DashMap<String, TimedDestSet>,
    window: Duration,
    threshold: usize,
}

impl LateralMovementDetector {
    pub fn new() -> Self {
        Self {
            state: DashMap::new(),
            window: Duration::from_secs(LATERAL_WINDOW_SECS),
            threshold: LATERAL_THRESHOLD,
        }
    }

    /// Process an alert. Only tracks internal-to-internal flows.
    pub fn process(&self, alert: &AlertMessage, detection_tx: &mpsc::Sender<DetectionEvent>) {
        // Only track internal-to-internal flows
        if !is_internal_ip(&alert.src_ip) || !is_internal_ip(&alert.dst_ip) {
            return;
        }

        let key = alert.src_ip.clone();
        let now = Instant::now();

        let should_alert = {
            let mut entry = self.state.entry(key.clone()).or_insert_with(|| TimedDestSet {
                dests: HashSet::new(),
                window_start: now,
            });

            let set = entry.value_mut();

            if now.duration_since(set.window_start) >= self.window {
                set.dests.clear();
                set.window_start = now;
            }

            set.dests.insert(alert.dst_ip.clone());

            if set.dests.len() >= self.threshold {
                Some(set.dests.len())
            } else {
                None
            }
        };

        if let Some(unique_dests) = should_alert {
            log!(DetectionLog::LateralMovementDetected(
                key.clone(),
                unique_dests,
                LATERAL_WINDOW_SECS,
            ));

            let event = DetectionEvent {
                source: DetectionSource::Correlation,
                attack_type: "threat_detected".to_string(),
                confidence: 0.75,
                source_ip: key.clone(),
                dest_ip: alert.dst_ip.clone(),
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
                entry.dests.clear();
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

/// Check if an IP address string represents a private/internal address.
/// RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// RFC 4193: fc00::/7 (IPv6 unique local)
pub fn is_internal_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };

    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7
            (segments[0] & 0xfe00) == 0xfc00
            // ::1 (loopback)
            || v6.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn make_alert(src_ip: &str, dst_ip: &str) -> AlertMessage {
        AlertMessage {
            timestamp: 0,
            flow_key: String::new(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port: 12345,
            dst_port: 445,
            protocol: 6,
            is_attack: true,
            attack_type: Some("Exploitation".to_string()),
            confidence: 0.8,
            ae_score: 0.4,
            anomaly_score: 0.0,
            c2_score: 0.0,
            packet_count: 50,
            flow_duration_us: 500_000,
        }
    }

    #[tokio::test]
    async fn lateral_threshold_triggers_for_internal_only() {
        let detector = LateralMovementDetector::new();
        let (tx, mut rx) = mpsc::channel(64);

        // Internal → external should be ignored
        detector.process(&make_alert("10.0.0.1", "8.8.8.8"), &tx);
        assert!(rx.try_recv().is_err());

        // Internal → internal, below threshold
        for i in 1..5 {
            detector.process(&make_alert("10.0.0.1", &format!("10.0.1.{i}")), &tx);
        }
        assert!(rx.try_recv().is_err(), "Should not alert below threshold");

        // 5th unique internal dest should trigger
        detector.process(&make_alert("10.0.0.1", "10.0.1.5"), &tx);
        let event = rx.try_recv().expect("Should alert at threshold");
        assert_eq!(event.source, DetectionSource::Correlation);
    }
}
