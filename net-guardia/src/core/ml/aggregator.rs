//! Per-flow detection aggregator.
//!
//! Records per-key hits within a rolling time window; callers decide when to
//! fire based on how many hits a given attack class needs (manifest-driven)
//! and how far the rolling-average score beats the confidence threshold.

use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::model::detection::ml_detection::FlowKey;

pub struct AttackAggregator {
    detections: DashMap<FlowKey, Vec<(Instant, f32)>>,
    window_duration: Duration,
}

impl AttackAggregator {
    pub fn new(window_secs: u64) -> Self {
        Self {
            detections: DashMap::new(),
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Record a detection and decide whether the flow should fire an alert.
    ///
    /// - `required_confirmations`: in-window hit count the flow must reach.
    ///   Resolved by the caller from the active manifest's per-label value;
    ///   validated at manifest load to be ≥ 1, so no runtime floor is needed.
    /// - `alert_multiplier`: scales `threshold` before the average-score
    ///   comparison, driven by the manifest's `thresholds.alert_multiplier`.
    pub fn should_alert(
        &self,
        flow_key: &FlowKey,
        score: f32,
        threshold: f32,
        required_confirmations: usize,
        alert_multiplier: f32,
    ) -> bool {
        let now = Instant::now();

        let mut detections = self.detections.entry(flow_key.clone()).or_default();
        detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
        detections.push((now, score));

        if detections.len() >= required_confirmations {
            let avg_score: f32 = detections.iter().map(|(_, s)| s).sum::<f32>() / detections.len() as f32;
            return avg_score > threshold * alert_multiplier;
        }

        false
    }

    pub fn cleanup(&self) {
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

    const TEST_MULTIPLIER: f32 = 1.2;

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
    fn required_three_fires_on_third_hit() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        assert!(!agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
        assert!(!agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key, 5.0, 1.0, 3, TEST_MULTIPLIER));
    }

    #[test]
    fn required_one_fires_immediately() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        assert!(agg.should_alert(&key, 5.0, 1.0, 1, TEST_MULTIPLIER));
    }

    #[test]
    fn required_six_needs_six_hits() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        for _ in 0..5 {
            assert!(!agg.should_alert(&key, 5.0, 1.0, 6, TEST_MULTIPLIER));
        }
        assert!(agg.should_alert(&key, 5.0, 1.0, 6, TEST_MULTIPLIER));
    }

    #[test]
    fn average_score_at_or_below_scaled_threshold_does_not_fire() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        // score 1.0, threshold 1.0, multiplier 1.2 → gate is 1.2; 1.0 misses.
        assert!(!agg.should_alert(&key, 1.0, 1.0, 1, TEST_MULTIPLIER));
    }

    #[test]
    fn larger_multiplier_raises_the_bar() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        // multiplier 2.5, threshold 1.0 → gate is 2.5; score 2.0 misses.
        assert!(!agg.should_alert(&key, 2.0, 1.0, 1, 2.5));
    }

    #[test]
    fn cleanup_preserves_fresh_entries() {
        let agg = AttackAggregator::new(60);
        let key = test_key();
        agg.should_alert(&key, 5.0, 1.0, 10, TEST_MULTIPLIER);
        assert!(agg.detections.contains_key(&key));
        agg.cleanup();
        assert!(agg.detections.contains_key(&key));
    }

    #[test]
    fn independent_flows_track_separately() {
        let agg = AttackAggregator::new(60);
        let key_a = test_key();
        let mut key_b = test_key();
        key_b.dst_port = 81;
        assert!(!agg.should_alert(&key_a, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(!agg.should_alert(&key_b, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key_a, 5.0, 1.0, 2, TEST_MULTIPLIER));
        assert!(agg.should_alert(&key_b, 5.0, 1.0, 2, TEST_MULTIPLIER));
    }
}
