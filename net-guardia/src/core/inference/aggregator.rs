use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::domain::detection::ml_detection::FlowKey;

const MAX_DETECTIONS_PER_FLOW: usize = 256;

pub struct AttackAggregator {
    detections: DashMap<FlowKey, Vec<(Instant, f32)>>,
    window_duration: Duration,
    max_flow_keys: usize,
}

impl AttackAggregator {
    pub fn new(window_secs: u64, max_flow_keys: usize) -> Self {
        Self {
            detections: DashMap::new(),
            window_duration: Duration::from_secs(window_secs),
            max_flow_keys: max_flow_keys.max(1),
        }
    }

    pub fn should_alert(
        &self,
        flow_key: &FlowKey,
        score: f32,
        threshold: f32,
        required_confirmations: usize,
        alert_multiplier: f32,
    ) -> bool {
        let now = Instant::now();

        if self.detections.len() >= self.max_flow_keys && self.detections.get(flow_key).is_none() {
            self.cleanup_at(now);
            if self.detections.len() >= self.max_flow_keys {
                return false;
            }
        }

        let mut detections = self.detections.entry(*flow_key).or_default();
        detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
        detections.push((now, score));
        let history_limit = MAX_DETECTIONS_PER_FLOW.max(required_confirmations);
        if detections.len() > history_limit {
            let excess = detections.len() - history_limit;
            detections.drain(0..excess);
        }

        if detections.len() < required_confirmations {
            return false;
        }

        let avg_score: f32 = detections.iter().map(|(_, s)| s).sum::<f32>() / detections.len() as f32;
        avg_score > threshold * alert_multiplier
    }

    pub fn cleanup(&self) {
        self.cleanup_at(Instant::now());
    }

    fn cleanup_at(&self, now: Instant) {
        self.detections.retain(|_, detections| {
            detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
            !detections.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::data_plane::ip_version::IpVersion;

    const TEST_MULTIPLIER: f32 = 1.2;

    fn aggregator() -> AttackAggregator {
        AttackAggregator::new(60, 1024)
    }

    fn test_key() -> FlowKey {
        FlowKey {
            src_ip: [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            ip_version: IpVersion::V4,
        }
    }

    #[test]
    fn required_three_fires_on_third_hit() {
        let agg = aggregator();
        let key = test_key();
        assert!(!agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
        assert!(!agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
    }

    #[test]
    fn required_one_fires_immediately() {
        let agg = aggregator();
        let key = test_key();
        assert!(agg.should_alert(&key, 5.0, 1.0, 1, TEST_MULTIPLIER));
    }

    #[test]
    fn required_six_needs_six_hits() {
        let agg = aggregator();
        let key = test_key();
        for _ in 0..5 {
            assert!(!agg.should_alert(&key, 5.0, 1.0, 6, TEST_MULTIPLIER));
        }
        assert!(agg.should_alert(&key, 5.0, 1.0, 6, TEST_MULTIPLIER));
    }

    #[test]
    fn average_score_at_or_below_scaled_threshold_does_not_fire() {
        let agg = aggregator();
        let key = test_key();
        assert!(!agg.should_alert(&key, 1.0, 1.0, 1, TEST_MULTIPLIER));
    }

    #[test]
    fn larger_multiplier_raises_the_bar() {
        let agg = aggregator();
        let key = test_key();
        assert!(!agg.should_alert(&key, 2.0, 1.0, 1, 2.5));
    }

    #[test]
    fn cleanup_preserves_fresh_entries() {
        let agg = aggregator();
        let key = test_key();
        agg.should_alert(&key, 5.0, 1.0, 10, TEST_MULTIPLIER);
        assert!(agg.detections.contains_key(&key));
        agg.cleanup();
        assert!(agg.detections.contains_key(&key));
    }

    #[test]
    fn independent_flows_track_separately() {
        let agg = aggregator();
        let key_a = test_key();
        let mut key_b = test_key();
        key_b.dst_port = 81;
        assert!(!agg.should_alert(&key_a, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(!agg.should_alert(&key_b, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key_a, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key_b, 5.0, 1.0, 2, TEST_MULTIPLIER));
    }

    #[test]
    fn detections_per_flow_are_bounded() {
        let agg = aggregator();
        let key = test_key();

        for _ in 0..(MAX_DETECTIONS_PER_FLOW + 10) {
            agg.should_alert(&key, 5.0, 1.0, 1, TEST_MULTIPLIER);
        }

        assert_eq!(
            agg.detections.get(&key).expect("flow entries").len(),
            MAX_DETECTIONS_PER_FLOW
        );
    }

    #[test]
    fn high_confirmation_requirement_sets_history_floor() {
        let agg = aggregator();
        let key = test_key();
        let required = MAX_DETECTIONS_PER_FLOW + 10;

        for _ in 0..required - 1 {
            assert!(!agg.should_alert(&key, 5.0, 1.0, required, TEST_MULTIPLIER));
        }

        assert!(agg.should_alert(&key, 5.0, 1.0, required, TEST_MULTIPLIER));
        assert_eq!(agg.detections.get(&key).expect("flow entries").len(), required);
    }

    #[test]
    fn new_flow_keys_are_bounded() {
        let agg = AttackAggregator::new(60, 1);
        let mut second_key = test_key();
        second_key.dst_port = 81;

        assert!(agg.should_alert(&test_key(), 5.0, 1.0, 1, TEST_MULTIPLIER));
        assert!(!agg.should_alert(&second_key, 5.0, 1.0, 1, TEST_MULTIPLIER));
        assert_eq!(agg.detections.len(), 1);
    }
}
