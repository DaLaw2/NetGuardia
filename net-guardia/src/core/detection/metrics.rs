use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::domain::common::event::DetectionSource;

const ORDER: Ordering = Ordering::Relaxed;

#[derive(Debug, Default)]
pub struct FusionMetrics {
    total_emits: AtomicU64,
    multi_source_emits: AtomicU64,
    windows_evicted: AtomicU64,
    ml_fires: AtomicU64,
    suricata_fires: AtomicU64,
    beaconing_fires: AtomicU64,
    correlation_fires: AtomicU64,
}

impl FusionMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_fire(&self, source: DetectionSource) {
        let counter = match source {
            DetectionSource::ML => &self.ml_fires,
            DetectionSource::Suricata => &self.suricata_fires,
            DetectionSource::Beaconing => &self.beaconing_fires,
            DetectionSource::Correlation => &self.correlation_fires,
        };
        counter.fetch_add(1, ORDER);
    }

    pub fn record_emit(&self, source_count: usize) {
        self.total_emits.fetch_add(1, ORDER);
        if source_count >= 2 {
            self.multi_source_emits.fetch_add(1, ORDER);
        }
    }

    pub fn record_eviction(&self) {
        self.windows_evicted.fetch_add(1, ORDER);
    }

    pub fn snapshot(&self) -> FusionMetricsSnapshot {
        let total_emits = self.total_emits.load(ORDER);
        let multi_source_emits = self.multi_source_emits.load(ORDER);
        let windows_evicted = self.windows_evicted.load(ORDER);

        let ml = self.ml_fires.load(ORDER);
        let suricata = self.suricata_fires.load(ORDER);
        let beaconing = self.beaconing_fires.load(ORDER);
        let correlation = self.correlation_fires.load(ORDER);

        let agreed_rate = ratio(multi_source_emits, total_emits);
        let drop_denominator = saturating_sum(&[total_emits, windows_evicted]);
        let window_drop_rate = ratio(windows_evicted, drop_denominator);

        let total_fires = saturating_sum(&[ml, suricata, beaconing, correlation]);
        let per_source_fire_rate = PerSourceRate {
            ml: ratio(ml, total_fires),
            suricata: ratio(suricata, total_fires),
            beaconing: ratio(beaconing, total_fires),
            correlation: ratio(correlation, total_fires),
        };

        FusionMetricsSnapshot {
            total_emits,
            multi_source_emits,
            agreed_rate,
            windows_evicted,
            window_drop_rate,
            per_source_fires: PerSourceCount {
                ml,
                suricata,
                beaconing,
                correlation,
            },
            per_source_fire_rate,
        }
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn saturating_sum(values: &[u64]) -> u64 {
    values.iter().copied().fold(0, u64::saturating_add)
}

#[derive(Debug, Clone, Serialize)]
pub struct FusionMetricsSnapshot {
    pub total_emits: u64,
    pub multi_source_emits: u64,
    pub agreed_rate: f64,
    pub windows_evicted: u64,
    pub window_drop_rate: f64,
    pub per_source_fires: PerSourceCount,
    pub per_source_fire_rate: PerSourceRate,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerSourceCount {
    pub ml: u64,
    pub suricata: u64,
    pub beaconing: u64,
    pub correlation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PerSourceRate {
    pub ml: f64,
    pub suricata: f64,
    pub beaconing: f64,
    pub correlation: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_traffic_snapshot_reports_zero_rates() {
        let m = FusionMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.total_emits, 0);
        assert_eq!(s.agreed_rate, 0.0);
        assert_eq!(s.window_drop_rate, 0.0);
        assert_eq!(s.per_source_fire_rate.ml, 0.0);
    }

    #[test]
    fn agreed_rate_reflects_multi_source_ratio() {
        let m = FusionMetrics::new();
        m.record_emit(1);
        m.record_emit(2);
        m.record_emit(3);
        m.record_emit(1);
        let s = m.snapshot();
        assert_eq!(s.total_emits, 4);
        assert_eq!(s.multi_source_emits, 2);
        assert!((s.agreed_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn window_drop_rate_isolates_evictions_from_emits() {
        let m = FusionMetrics::new();
        for _ in 0..9 {
            m.record_emit(1);
        }
        m.record_eviction();
        let s = m.snapshot();
        assert_eq!(s.windows_evicted, 1);
        assert!((s.window_drop_rate - 0.1).abs() < 1e-9);
    }

    #[test]
    fn per_source_fire_rate_sums_to_one_when_nonzero() {
        let m = FusionMetrics::new();
        m.record_fire(DetectionSource::ML);
        m.record_fire(DetectionSource::ML);
        m.record_fire(DetectionSource::Suricata);
        m.record_fire(DetectionSource::Beaconing);
        let s = m.snapshot();
        let sum = s.per_source_fire_rate.ml
            + s.per_source_fire_rate.suricata
            + s.per_source_fire_rate.beaconing
            + s.per_source_fire_rate.correlation;
        assert!((sum - 1.0).abs() < 1e-9, "per-source rates must sum to 1, got {sum}");
        assert!((s.per_source_fire_rate.ml - 0.5).abs() < 1e-9);
    }

    #[test]
    fn record_fire_routes_to_correct_source_bucket() {
        let m = FusionMetrics::new();
        m.record_fire(DetectionSource::Suricata);
        m.record_fire(DetectionSource::Correlation);
        let s = m.snapshot();
        assert_eq!(s.per_source_fires.suricata, 1);
        assert_eq!(s.per_source_fires.correlation, 1);
        assert_eq!(s.per_source_fires.ml, 0);
        assert_eq!(s.per_source_fires.beaconing, 0);
    }

    #[test]
    fn snapshot_saturates_counter_totals() {
        let m = FusionMetrics::new();
        m.total_emits.store(u64::MAX, ORDER);
        m.windows_evicted.store(1, ORDER);
        m.ml_fires.store(u64::MAX, ORDER);
        m.suricata_fires.store(1, ORDER);

        let s = m.snapshot();

        assert!(s.window_drop_rate.is_finite());
        assert!(s.per_source_fire_rate.ml.is_finite());
        assert!(s.per_source_fire_rate.suricata.is_finite());
        assert!(s.window_drop_rate >= 0.0);
        assert!(s.per_source_fire_rate.ml <= 1.0);
    }
}
