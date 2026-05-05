use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio::time::interval;

use crate::core::correlation::botnet::BotnetDetector;
use crate::core::correlation::lateral::LateralMovementDetector;
use crate::core::correlation::scan::ScanDetector;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::DetectionEvent;
use crate::domain::detection::log::DetectionLog;
use crate::domain::detection::ml_detection::AlertMessage;

/// Coordinates cross-flow correlation detectors (botnet, scan, lateral movement).
/// Subscribes to ML AlertMessage broadcast and feeds enriched DetectionEvents
/// to the DetectionOrchestrator for dedup and SOAR routing.
pub struct CorrelationEngine {
    botnet: BotnetDetector,
    scan: ScanDetector,
    lateral: LateralMovementDetector,
    alert_rx: broadcast::Receiver<AlertMessage>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    cleanup_interval_secs: u64,
}

impl CorrelationEngine {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        alert_rx: broadcast::Receiver<AlertMessage>,
        detection_tx: mpsc::Sender<DetectionEvent>,
    ) -> Self {
        let cfg = app_config.load();
        let correlation = &cfg.correlation;
        let max_tracked = correlation.max_tracked_entries;
        Self {
            botnet: BotnetDetector::new(&correlation.botnet, max_tracked),
            scan: ScanDetector::new(&correlation.scan, max_tracked),
            lateral: LateralMovementDetector::new(&correlation.lateral, max_tracked),
            alert_rx,
            detection_tx,
            cleanup_interval_secs: cfg.detection.cleanup_interval_secs,
        }
    }

    /// Spawn the correlation engine as a background task.
    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::CorrelationEngineStarted);

        let mut cleanup_interval = interval(Duration::from_secs(self.cleanup_interval_secs));

        loop {
            tokio::select! {
                result = self.alert_rx.recv() => {
                    match result {
                        Ok(alert) => self.process_alert(&alert),
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup();
                }
            }
        }
    }

    fn process_alert(&self, alert: &AlertMessage) {
        if let Some(event) = self.botnet.process(alert) {
            send_or_log(&self.detection_tx, event);
        }
        if let Some(event) = self.scan.process(alert) {
            send_or_log(&self.detection_tx, event);
        }
        if let Some(event) = self.lateral.process(alert) {
            send_or_log(&self.detection_tx, event);
        }
    }

    fn cleanup(&self) {
        let removed = self.botnet.cleanup() + self.scan.cleanup() + self.lateral.cleanup();
        if removed > 0 {
            log!(DetectionLog::CorrelationCleanup(removed));
        }
    }
}

fn send_or_log(tx: &mpsc::Sender<DetectionEvent>, event: DetectionEvent) {
    if let Err(mpsc::error::TrySendError::Full(dropped)) = tx.try_send(event) {
        log!(DetectionLog::DetectionChannelDrop(
            format!("{:?}", dropped.source),
            dropped.attack_type,
            dropped.source_ip,
        ));
    }
}
