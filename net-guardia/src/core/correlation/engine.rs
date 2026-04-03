use std::time::Duration;

use macros::log;
use tokio::sync::{broadcast, mpsc};

use crate::core::correlation::botnet::BotnetDetector;
use crate::core::correlation::lateral::LateralMovementDetector;
use crate::core::correlation::scan::ScanDetector;
use crate::model::detection::ml_detection::AlertMessage;
use crate::model::event::DetectionEvent;
use crate::model::log::detection::DetectionLog;

/// How often to sweep expired correlation state.
const CLEANUP_INTERVAL_SECS: u64 = 60;

/// Coordinates cross-flow correlation detectors (botnet, scan, lateral movement).
/// Subscribes to ML AlertMessage broadcast and feeds enriched DetectionEvents
/// to the DetectionOrchestrator for dedup and SOAR routing.
pub struct CorrelationEngine {
    botnet: BotnetDetector,
    scan: ScanDetector,
    lateral: LateralMovementDetector,
    alert_rx: broadcast::Receiver<AlertMessage>,
    detection_tx: mpsc::Sender<DetectionEvent>,
}

impl CorrelationEngine {
    pub fn new(alert_rx: broadcast::Receiver<AlertMessage>, detection_tx: mpsc::Sender<DetectionEvent>) -> Self {
        Self {
            botnet: BotnetDetector::new(),
            scan: ScanDetector::new(),
            lateral: LateralMovementDetector::new(),
            alert_rx,
            detection_tx,
        }
    }

    /// Spawn the correlation engine as a background task.
    pub fn start(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(mut self) {
        log!(DetectionLog::CorrelationEngineStarted);

        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));

        loop {
            tokio::select! {
                result = self.alert_rx.recv() => {
                    match result {
                        Ok(alert) => self.process_alert(&alert),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup();
                }
            }
        }
    }

    fn process_alert(&self, alert: &AlertMessage) {
        self.botnet.process(alert, &self.detection_tx);
        self.scan.process(alert, &self.detection_tx);
        self.lateral.process(alert, &self.detection_tx);
    }

    fn cleanup(&self) {
        let removed = self.botnet.cleanup() + self.scan.cleanup() + self.lateral.cleanup();
        if removed > 0 {
            log!(DetectionLog::CorrelationCleanup { removed });
        }
    }
}
