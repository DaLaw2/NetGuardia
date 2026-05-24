use std::time::{SystemTime, UNIX_EPOCH};

use macros::log;
use tokio::sync::broadcast;

use crate::domain::detection::log::MLLog;
use crate::domain::detection::ml_detection::{AlertMessage, DetectionResult};

pub struct MLAlert {
    broadcast_tx: broadcast::Sender<AlertMessage>,
}

impl MLAlert {
    pub fn new(channel_capacity: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(channel_capacity.max(1));

        MLAlert { broadcast_tx }
    }

    pub fn subscribe_to_alerts(&self) -> broadcast::Receiver<AlertMessage> {
        self.broadcast_tx.subscribe()
    }

    pub fn broadcast_alert(&self, result: &DetectionResult) {
        if self.broadcast_tx.receiver_count() > 0 {
            let alert = AlertMessage::from_detection_result(result, current_epoch_secs());
            if let Err(e) = self.broadcast_tx.send(alert) {
                log!(MLLog::BroadcastAlertFailed(e.to_string()));
            }
        }
    }
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
