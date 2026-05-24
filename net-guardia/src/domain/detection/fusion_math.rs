use crate::domain::common::event::DetectionSource;

pub fn fused_confidence(per_source: &[f32]) -> f32 {
    if per_source.is_empty() {
        return 0.0;
    }
    let mut inverse: f64 = 1.0;
    for &c in per_source {
        let clamped = sanitize_confidence(c);
        inverse *= 1.0 - clamped;
    }
    (1.0 - inverse).clamp(0.0, 1.0) as f32
}

fn sanitize_confidence(confidence: f32) -> f64 {
    let value = confidence as f64;
    if value.is_nan() { 0.0 } else { value.clamp(0.0, 1.0) }
}

#[derive(Debug, Clone, Copy)]
pub struct FusionWindowLengths {
    pub suricata_secs: u64,
    pub cv_secs: u64,
    pub ml_secs: u64,
    pub graph_secs: u64,
}

pub const FUSION_WINDOW_MIN_SECS: u64 = 1;
pub const FUSION_WINDOW_MAX_SECS: u64 = 30;

impl Default for FusionWindowLengths {
    fn default() -> Self {
        Self {
            suricata_secs: 10,
            cv_secs: 8,
            ml_secs: 2,
            graph_secs: 5,
        }
    }
}

impl FusionWindowLengths {
    pub fn for_source(&self, source: DetectionSource) -> u64 {
        let raw = match source {
            DetectionSource::Suricata => self.suricata_secs,
            DetectionSource::Beaconing => self.cv_secs,
            DetectionSource::ML => self.ml_secs,
            DetectionSource::Correlation => self.graph_secs,
        };
        raw.clamp(FUSION_WINDOW_MIN_SECS, FUSION_WINDOW_MAX_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_fusion_returns_zero() {
        assert_eq!(fused_confidence(&[]), 0.0);
    }

    #[test]
    fn single_source_passes_through() {
        assert!((fused_confidence(&[0.8]) - 0.8).abs() < 1e-5);
        assert_eq!(fused_confidence(&[0.0]), 0.0);
        assert_eq!(fused_confidence(&[1.0]), 1.0);
    }

    #[test]
    fn two_sources_boost() {
        let got = fused_confidence(&[0.7, 0.9]);
        assert!((got - 0.97).abs() < 1e-5);
    }

    #[test]
    fn three_sources_monotone_in_count() {
        let two = fused_confidence(&[0.6, 0.7]);
        let three = fused_confidence(&[0.6, 0.7, 0.5]);
        assert!(three >= two);
    }

    #[test]
    fn four_sources_bounded() {
        let four = fused_confidence(&[0.9, 0.8, 0.7, 0.6]);
        assert!(four < 1.0);
        assert!(four > 0.99);
    }

    #[test]
    fn out_of_range_confidences_are_clamped() {
        assert_eq!(fused_confidence(&[-0.5, -0.1]), 0.0);
        assert_eq!(fused_confidence(&[2.0, 3.0]), 1.0);
    }

    #[test]
    fn non_finite_confidences_stay_bounded() {
        assert_eq!(fused_confidence(&[f32::NAN, 0.75]), 0.75);
        assert_eq!(fused_confidence(&[f32::INFINITY]), 1.0);
        assert_eq!(fused_confidence(&[f32::NEG_INFINITY]), 0.0);
    }

    #[test]
    fn window_lengths_defaults() {
        let w = FusionWindowLengths::default();
        assert_eq!(w.for_source(DetectionSource::Suricata), 10);
        assert_eq!(w.for_source(DetectionSource::Beaconing), 8);
        assert_eq!(w.for_source(DetectionSource::ML), 2);
        assert_eq!(w.for_source(DetectionSource::Correlation), 5);
    }

    #[test]
    fn window_lengths_clamped_to_range() {
        let w = FusionWindowLengths {
            suricata_secs: 999,
            cv_secs: 0,
            ml_secs: 2,
            graph_secs: 5,
        };
        assert_eq!(w.for_source(DetectionSource::Suricata), 30);
        assert_eq!(w.for_source(DetectionSource::Beaconing), 1);
    }
}
