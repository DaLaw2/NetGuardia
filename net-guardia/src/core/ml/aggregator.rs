use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::model::ml_detection::FlowKey;

pub struct AttackAggregator {
    detections: HashMap<FlowKey, Vec<(Instant, f32)>>,
    window_duration: Duration,
    min_detections: usize,
    alert_threshold_multiplier: f32,
}

impl AttackAggregator {
    pub fn new(window_secs: u64, min_detections: usize) -> Self {
        Self {
            detections: HashMap::new(),
            window_duration: Duration::from_secs(window_secs),
            min_detections,
            alert_threshold_multiplier: 1.2,
        }
    }

    pub fn should_alert(&mut self, flow_key: &FlowKey, score: f32, threshold: f32, attack_type: Option<&str>) -> bool {
        let now = Instant::now();

        let detections = self.detections.entry(flow_key.clone()).or_default();
        detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
        detections.push((now, score));

        // Per-attack-type adaptive min_detections:
        // DDoS/DoS: high frequency, need more confirmations to avoid alert storms
        // C2/Cryptomining: low frequency, alert on first detection
        let effective_min = match attack_type {
            Some("DDoS") | Some("DoS") => self.min_detections.saturating_mul(2).max(1),
            Some("C2 Communication") | Some("Cryptomining") => 1,
            _ => self.min_detections,
        };

        if detections.len() >= effective_min {
            let avg_score: f32 = detections.iter().map(|(_, s)| s).sum::<f32>() / detections.len() as f32;

            return avg_score > threshold * self.alert_threshold_multiplier;
        }

        false
    }

    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.detections.retain(|_, detections| {
            detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
            !detections.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> FlowKey {
        FlowKey {
            src_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            ip_version: 4,
        }
    }

    #[test]
    fn default_attack_type_uses_base_min_detections() {
        let mut agg = AttackAggregator::new(60, 3);
        let key = test_key();
        // Need 3 detections for default type
        assert!(!agg.should_alert(&key, 5.0, 1.0, Some("Brute Force")));
        assert!(!agg.should_alert(&key, 5.0, 1.0, Some("Brute Force")));
        assert!(agg.should_alert(&key, 5.0, 1.0, Some("Brute Force")));
    }

    #[test]
    fn ddos_requires_double_min_detections() {
        let mut agg = AttackAggregator::new(60, 3);
        let key = test_key();
        // DDoS needs 6 detections (3 * 2)
        for _ in 0..5 {
            assert!(!agg.should_alert(&key, 5.0, 1.0, Some("DDoS")));
        }
        assert!(agg.should_alert(&key, 5.0, 1.0, Some("DDoS")));
    }

    #[test]
    fn c2_alerts_on_first_detection() {
        let mut agg = AttackAggregator::new(60, 3);
        let key = test_key();
        // C2 Communication alerts immediately (min=1)
        assert!(agg.should_alert(&key, 5.0, 1.0, Some("C2 Communication")));
    }

    #[test]
    fn cryptomining_alerts_on_first_detection() {
        let mut agg = AttackAggregator::new(60, 3);
        let key = test_key();
        assert!(agg.should_alert(&key, 5.0, 1.0, Some("Cryptomining")));
    }

    #[test]
    fn none_attack_type_uses_default() {
        let mut agg = AttackAggregator::new(60, 3);
        let key = test_key();
        assert!(!agg.should_alert(&key, 5.0, 1.0, None));
        assert!(!agg.should_alert(&key, 5.0, 1.0, None));
        assert!(agg.should_alert(&key, 5.0, 1.0, None));
    }
}
