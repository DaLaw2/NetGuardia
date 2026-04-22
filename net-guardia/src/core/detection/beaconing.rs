use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use crate::domain::common::config::AppConfig;
use crate::domain::common::event::DetectionEvent;
use crate::domain::detection::beaconing::BeaconingState;
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;

pub struct BeaconingDetector {
    state: BeaconingState,
    alert_rx: broadcast::Receiver<AlertMessage>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    analysis_interval_secs: u64,
}

impl BeaconingDetector {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        alert_rx: broadcast::Receiver<AlertMessage>,
        detection_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        let cfg = app_config.load();
        let beaconing = &cfg.detection.beaconing;
        Self {
            state: BeaconingState::new(
                beaconing.min_observations,
                beaconing.cv_threshold,
                beaconing.max_cache_entries,
                beaconing.expiry_secs,
                beaconing.alert_cooldown_secs,
            ),
            alert_rx,
            detection_tx,
            analysis_interval_secs: beaconing.analysis_interval_secs,
        }
    }

    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::BeaconingDetectorStarted);
        let mut analysis_interval = interval(Duration::from_secs(self.analysis_interval_secs));
        loop {
            tokio::select! {
                result = self.alert_rx.recv() => {
                    match result {
                        Ok(alert) => self.state.record_flow(&alert),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = analysis_interval.tick() => {
                    for event in self.state.analyze() {
                        if let Err(mpsc::error::TrySendError::Full(d)) = self.detection_tx.try_send(event) {
                            log!(DetectionLog::DetectionChannelDrop(
                                format!("{:?}", d.source),
                                d.attack_type,
                                d.source_ip,
                            ));
                        }
                    }
                    self.state.cleanup();
                }
            }
        }
    }
}
