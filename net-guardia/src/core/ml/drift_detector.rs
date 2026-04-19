use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use crate::model::detection::drift::{DriftReport, FeatureBaselines};

/// Maximum number of snapshots to retain, preventing unbounded memory growth.
const MAX_SNAPSHOTS: usize = 10_000;

/// Channel depth for the owner-task command queue. With a typical inference
/// batch of 100 flows per second, 1024 gives ~10s of cushion before the
/// hot path begins shedding samples.
const DRIFT_CMD_CHANNEL_CAPACITY: usize = 1024;

/// Tracks rolling mean/stddev of normalized input features over a configurable window.
/// Compares against training-time baselines to detect data drift.
pub struct DriftDetector {
    /// Recent feature snapshots within the rolling window, capped at MAX_SNAPSHOTS.
    snapshots: VecDeque<(Instant, Vec<f64>)>,
    /// Number of features expected per snapshot.
    num_features: usize,
    /// Feature baselines (if available).
    baselines: Option<FeatureBaselines>,
    /// Rolling window duration (runtime-configurable via DB `ml_drift_window_secs`).
    drift_window: Duration,
}

impl DriftDetector {
    /// Create a new detector with a configurable drift window duration.
    /// Default window is 3600s (1 hour) when not specified via DB setting `ml_drift_window_secs`.
    pub fn new(baselines: Option<FeatureBaselines>, drift_window: Duration) -> Self {
        let num_features = baselines.as_ref().map_or(0, |b| b.names.len());
        Self {
            snapshots: VecDeque::new(),
            num_features,
            baselines,
            drift_window,
        }
    }

    /// Add a new feature snapshot and evict stale entries.
    pub fn update(&mut self, features: &[f64]) {
        let now = Instant::now();
        self.snapshots.push_back((now, features.to_vec()));
        self.evict_stale(now);
        // Cap total snapshots to prevent unbounded memory growth
        while self.snapshots.len() > MAX_SNAPSHOTS {
            self.snapshots.pop_front();
        }
    }

    /// Check whether the current rolling mean has drifted > 3σ from baseline.
    pub fn check_drift(&self) -> Option<DriftReport> {
        let baselines = self.baselines.as_ref()?;
        if self.snapshots.is_empty() || self.num_features == 0 {
            return None;
        }

        let n = self.snapshots.len() as f64;
        let mut sums = vec![0.0_f64; self.num_features];

        for (_, features) in &self.snapshots {
            for (i, &val) in features.iter().enumerate().take(self.num_features) {
                sums[i] += val;
            }
        }

        let mut drifted_features = Vec::new();
        let mut max_deviation = 0.0_f64;

        for (i, (sum, (bl_mean, bl_std))) in sums
            .iter()
            .zip(baselines.means.iter().zip(baselines.stds.iter()))
            .enumerate()
            .take(self.num_features)
        {
            let current_mean = sum / n;

            // Skip features with zero or near-zero stddev (constant features)
            if *bl_std < 1e-12 {
                continue;
            }

            let deviation = ((current_mean - bl_mean) / bl_std).abs();
            if deviation > 3.0 {
                drifted_features.push(baselines.names[i].clone());
                if deviation > max_deviation {
                    max_deviation = deviation;
                }
            }
        }

        if drifted_features.is_empty() {
            None
        } else {
            Some(DriftReport {
                drifted_features,
                max_deviation,
            })
        }
    }

    /// Remove snapshots older than the configured drift window.
    fn evict_stale(&mut self, now: Instant) {
        while let Some((ts, _)) = self.snapshots.front() {
            if now.duration_since(*ts) > self.drift_window {
                self.snapshots.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Command queue between drift-detector callers and the owner task.
enum DriftCmd {
    Update(Vec<f64>),
    CheckDrift {
        reply: oneshot::Sender<Option<DriftReport>>,
    },
}

/// Lock-free handle to a `DriftDetector` running on its own tokio task.
///
/// The hot path is `update`, called from the ML engine's inference tick on
/// the spawn-blocking pool — it must not await, so we use `try_send` and
/// silently drop the sample when the channel is full. Drift is a statistical
/// signal computed over thousands of snapshots in a window; losing a few
/// samples under back-pressure does not change the verdict.
///
/// `check_drift` is called from the periodic drift monitor (tokio task), so
/// it can `await` the round-trip naturally.
#[derive(Clone)]
pub struct DriftDetectorHandle {
    tx: mpsc::Sender<DriftCmd>,
}

impl DriftDetectorHandle {
    /// Spawn the owner task on the current tokio runtime and return a handle.
    pub fn spawn(baselines: Option<FeatureBaselines>, drift_window: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<DriftCmd>(DRIFT_CMD_CHANNEL_CAPACITY);
        tokio::spawn(async move {
            let mut detector = DriftDetector::new(baselines, drift_window);
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    DriftCmd::Update(features) => detector.update(&features),
                    DriftCmd::CheckDrift { reply } => {
                        let _ = reply.send(detector.check_drift());
                    }
                }
            }
        });
        Self { tx }
    }

    /// Fire-and-forget update. Drops the sample silently when the channel is
    /// full or the owner task has shut down (statistical tolerance — see the
    /// type-level doc).
    pub fn update(&self, features: Vec<f64>) {
        let _ = self.tx.try_send(DriftCmd::Update(features));
    }

    /// Round-trip drift query. Returns `None` if the channel is closed.
    pub async fn check_drift(&self) -> Option<DriftReport> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.tx.send(DriftCmd::CheckDrift { reply: reply_tx }).await.is_err() {
            return None;
        }
        reply_rx.await.unwrap_or(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_baselines(n: usize) -> FeatureBaselines {
        FeatureBaselines {
            names: (0..n).map(|i| format!("feature_{i}")).collect(),
            means: vec![0.0; n],
            stds: vec![1.0; n],
        }
    }

    #[test]
    fn no_drift_when_within_threshold() {
        let baselines = make_baselines(3);
        let mut detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600));
        // Values within 3σ of baseline mean 0.0 with std 1.0
        detector.update(&[1.0, -1.0, 2.0]);
        detector.update(&[0.5, -0.5, 1.5]);
        assert!(detector.check_drift().is_none());
    }

    #[test]
    fn drift_detected_when_exceeds_threshold() {
        let baselines = make_baselines(3);
        let mut detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600));
        // Mean of 5.0 exceeds 3σ from baseline mean 0.0
        detector.update(&[5.0, 0.0, 0.0]);
        detector.update(&[5.0, 0.0, 0.0]);
        let report = detector.check_drift().unwrap();
        assert!(report.drifted_features.contains(&"feature_0".to_string()));
        assert!(report.max_deviation > 3.0);
    }

    #[test]
    fn no_baselines_means_no_drift() {
        let mut detector = DriftDetector::new(None, Duration::from_secs(3600));
        detector.update(&[100.0, 200.0]);
        assert!(detector.check_drift().is_none());
    }

    #[test]
    fn empty_snapshots_no_drift() {
        let baselines = make_baselines(3);
        let detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600));
        assert!(detector.check_drift().is_none());
    }
}
