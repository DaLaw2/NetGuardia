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

    pub fn should_alert(&mut self, flow_key: &FlowKey, score: f32, threshold: f32) -> bool {
        let now = Instant::now();

        let detections = self.detections.entry(flow_key.clone()).or_default();
        detections.retain(|(time, _)| now.duration_since(*time) < self.window_duration);
        detections.push((now, score));

        if detections.len() >= self.min_detections {
            let avg_score: f32 =
                detections.iter().map(|(_, s)| s).sum::<f32>() / detections.len() as f32;

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