use std::collections::VecDeque;
use std::time::{Duration, Instant};

use macros::log;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::interval;

use crate::domain::common::event::DriftDetectedEvent;
use crate::domain::common::log::system::SystemLog;
use crate::domain::detection::drift::{DriftReport, FeatureBaselines};

enum DriftCmd {
    Update(Vec<f64>),
    CheckDrift {
        reply: oneshot::Sender<Option<DriftReport>>,
    },
}

#[derive(Clone)]
pub struct DriftDetectorHandle {
    tx: mpsc::Sender<DriftCmd>,
}

impl DriftDetectorHandle {
    pub fn spawn(
        baselines: Option<FeatureBaselines>,
        drift_window: Duration,
        max_snapshots: usize,
        channel_capacity: usize,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<DriftCmd>(channel_capacity);
        tokio::spawn(async move {
            let mut detector = DriftDetector::new(baselines, drift_window, max_snapshots);
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

    pub fn update(&self, features: Vec<f64>) {
        let _ = self.tx.try_send(DriftCmd::Update(features));
    }

    pub async fn check_drift(&self) -> Option<DriftReport> {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self.tx.send(DriftCmd::CheckDrift { reply: reply_tx }).await.is_err() {
            return None;
        }
        reply_rx.await.unwrap_or(None)
    }
}

pub struct DriftDetector {
    snapshots: VecDeque<(Instant, Vec<f64>)>,
    num_features: usize,
    baselines: Option<FeatureBaselines>,
    drift_window: Duration,
    max_snapshots: usize,
}

impl DriftDetector {
    pub fn new(baselines: Option<FeatureBaselines>, drift_window: Duration, max_snapshots: usize) -> Self {
        let num_features = baselines.as_ref().map_or(0, |b| b.names.len());
        Self {
            snapshots: VecDeque::new(),
            num_features,
            baselines,
            drift_window,
            max_snapshots,
        }
    }

    pub fn update(&mut self, features: &[f64]) {
        let now = Instant::now();
        self.snapshots.push_back((now, features.to_vec()));
        self.evict_stale(now);
        while self.snapshots.len() > self.max_snapshots {
            self.snapshots.pop_front();
        }
    }

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

pub async fn run_drift_monitor(drift_detector: DriftDetectorHandle, drift_tx: broadcast::Sender<DriftDetectedEvent>) {
    let mut tick = interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        if let Some(report) = drift_detector.check_drift().await {
            log!(SystemLog::DriftDetected(
                report.drifted_features.len(),
                report.max_deviation
            ));
            let event = DriftDetectedEvent {
                drifted_features: report.drifted_features,
                max_deviation: report.max_deviation,
            };
            let _ = drift_tx.send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::core::inference::drift_detector::DriftDetector;
    use crate::domain::detection::drift::FeatureBaselines;

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
        let mut detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600), 10_000);
        detector.update(&[1.0, -1.0, 2.0]);
        detector.update(&[0.5, -0.5, 1.5]);
        assert!(detector.check_drift().is_none());
    }

    #[test]
    fn drift_detected_when_exceeds_threshold() {
        let baselines = make_baselines(3);
        let mut detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600), 10_000);
        detector.update(&[5.0, 0.0, 0.0]);
        detector.update(&[5.0, 0.0, 0.0]);
        let report = detector.check_drift().unwrap();
        assert!(report.drifted_features.contains(&"feature_0".to_string()));
        assert!(report.max_deviation > 3.0);
    }

    #[test]
    fn no_baselines_means_no_drift() {
        let mut detector = DriftDetector::new(None, Duration::from_secs(3600), 10_000);
        detector.update(&[100.0, 200.0]);
        assert!(detector.check_drift().is_none());
    }

    #[test]
    fn empty_snapshots_no_drift() {
        let baselines = make_baselines(3);
        let detector = DriftDetector::new(Some(baselines), Duration::from_secs(3600), 10_000);
        assert!(detector.check_drift().is_none());
    }
}
