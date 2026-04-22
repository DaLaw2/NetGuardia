use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::domain::detection::drift::{DriftReport, FeatureBaselines};
use crate::domain::detection::drift_detector::DriftDetector;

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
