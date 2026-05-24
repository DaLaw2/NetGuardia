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
use crate::core::detection::send_detection_or_log;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::DetectionEvent;
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::log::DetectionLog;

pub struct CorrelationEngine {
    botnet: BotnetDetector,
    scan: ScanDetector,
    lateral: LateralMovementDetector,
    alert_rx: broadcast::Receiver<FlowObservation>,
    detection_tx: mpsc::Sender<DetectionEvent>,
    cleanup_interval_secs: u64,
}

impl CorrelationEngine {
    pub fn new(
        app_config: &Arc<ArcSwap<AppConfig>>,
        alert_rx: broadcast::Receiver<FlowObservation>,
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

    pub async fn run(mut self) {
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

    fn process_alert(&self, alert: &FlowObservation) {
        if let Some(event) = self.botnet.process(alert) {
            let _ = send_detection_or_log(&self.detection_tx, event);
        }
        if let Some(event) = self.scan.process(alert) {
            let _ = send_detection_or_log(&self.detection_tx, event);
        }
        if let Some(event) = self.lateral.process(alert) {
            let _ = send_detection_or_log(&self.detection_tx, event);
        }
    }

    fn cleanup(&self) {
        let removed = self.botnet.cleanup() + self.scan.cleanup() + self.lateral.cleanup();
        if removed > 0 {
            log!(DetectionLog::CorrelationCleanup(removed));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use crate::core::detection::send_detection_or_log;
    use crate::domain::common::event::{DetectionEvent, DetectionSource};

    fn detection_event() -> DetectionEvent {
        DetectionEvent {
            source: DetectionSource::Correlation,
            attack_type: "scan".to_string(),
            confidence: 0.9,
            source_ip: "192.0.2.10".to_string(),
            dest_ip: "198.51.100.20".to_string(),
            protocol: 6,
            packet_count: 10,
            flow_duration_us: 1_000,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        }
    }

    #[test]
    fn send_detection_or_log_reports_success() {
        let (tx, _rx) = mpsc::channel(1);

        assert!(send_detection_or_log(&tx, detection_event()));
    }

    #[test]
    fn send_detection_or_log_reports_full_channel_drop() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(detection_event()).unwrap();

        assert!(!send_detection_or_log(&tx, detection_event()));
    }

    #[test]
    fn send_detection_or_log_reports_closed_channel_drop() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        assert!(!send_detection_or_log(&tx, detection_event()));
    }
}
