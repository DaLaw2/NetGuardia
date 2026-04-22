//! Lock-free fusion observability counters. The orchestrator bumps these
//! on ingress / emit / eviction; HTTP handlers (and eventually the admin
//! dashboard) read atomic snapshots without touching orchestrator state.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::domain::common::event::DetectionSource;

/// Relaxed ordering is enough for counters: readers tolerate arbitrary
/// interleaving, and no counter's value gates access to another memory
/// location. Anything stronger would just waste fence instructions on the
/// hot packet path without adding any real invariant.
const ORDER: Ordering = Ordering::Relaxed;

/// Atomic counters maintained by the detection orchestrator. Shared via
/// `Arc` with the HTTP metrics handler so dashboards can read without
/// blocking the orchestrator task.
#[derive(Debug, Default)]
pub struct FusionMetrics {
    /// Total fused emits (single-source + multi-source combined).
    total_emits: AtomicU64,
    /// Fused emits whose final `active_source_count` was ≥ 2 (i.e. fusion
    /// actually fired across multiple sources rather than single-source solo).
    multi_source_emits: AtomicU64,
    /// Fusion windows evicted under LRU pressure before they could emit.
    /// Kept separate from shutdown-drain drops — those are legitimate.
    windows_evicted: AtomicU64,
    /// Per-source event count. Increments once per ingress detection
    /// regardless of whether the event fires a fused emit downstream.
    ml_fires: AtomicU64,
    suricata_fires: AtomicU64,
    beaconing_fires: AtomicU64,
    correlation_fires: AtomicU64,
}

impl FusionMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an ingress detection from the given source. Called before
    /// fusion-window bookkeeping so per-source counters reflect raw
    /// volume, not what survives dedup.
    pub fn record_fire(&self, source: DetectionSource) {
        let counter = match source {
            DetectionSource::ML => &self.ml_fires,
            DetectionSource::Suricata => &self.suricata_fires,
            DetectionSource::Beaconing => &self.beaconing_fires,
            DetectionSource::Correlation => &self.correlation_fires,
        };
        counter.fetch_add(1, ORDER);
    }

    /// Record a fused emit. `source_count` is the number of distinct
    /// sources that contributed to this emit — 1 for single-source,
    /// 2..=4 when fusion actually agreed.
    pub fn record_emit(&self, source_count: usize) {
        self.total_emits.fetch_add(1, ORDER);
        if source_count >= 2 {
            self.multi_source_emits.fetch_add(1, ORDER);
        }
    }

    /// Record a fusion-window eviction that happened before the window
    /// could emit. Shutdown-drain drops are not counted here.
    pub fn record_eviction(&self) {
        self.windows_evicted.fetch_add(1, ORDER);
    }

    /// Take an atomic snapshot of every counter and derive the three
    /// rate figures the dashboard surfaces.
    pub fn snapshot(&self) -> FusionMetricsSnapshot {
        let total_emits = self.total_emits.load(ORDER);
        let multi_source_emits = self.multi_source_emits.load(ORDER);
        let windows_evicted = self.windows_evicted.load(ORDER);

        let ml = self.ml_fires.load(ORDER);
        let suricata = self.suricata_fires.load(ORDER);
        let beaconing = self.beaconing_fires.load(ORDER);
        let correlation = self.correlation_fires.load(ORDER);

        let agreed_rate = ratio(multi_source_emits, total_emits);
        let drop_denominator = total_emits + windows_evicted;
        let window_drop_rate = ratio(windows_evicted, drop_denominator);

        let total_fires = ml + suricata + beaconing + correlation;
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

/// Return `numerator / denominator` as `f64`, or `0.0` when the
/// denominator is zero. Saves every rate caller from an `if denom == 0`
/// rewrite of the same guard.
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Wire-format snapshot consumed by `GET /api/fusion/metrics`. Derived
/// fields (`agreed_rate`, `window_drop_rate`, `per_source_fire_rate`)
/// are precomputed server-side so the UI doesn't have to re-implement
/// the formulas and drift.
#[derive(Debug, Clone, Serialize)]
pub struct FusionMetricsSnapshot {
    pub total_emits: u64,
    pub multi_source_emits: u64,
    /// `multi_source_emits / total_emits`.
    pub agreed_rate: f64,
    pub windows_evicted: u64,
    /// `windows_evicted / (windows_evicted + total_emits)`.
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
        m.record_emit(1); // single-source
        m.record_emit(2); // multi
        m.record_emit(3); // multi
        m.record_emit(1); // single
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
        m.record_eviction(); // 1 evicted / 10 total tracked
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
}
