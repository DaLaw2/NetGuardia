use macros::log;
use tokio::sync::broadcast;

use crate::model::log::ml::MLLog;
use crate::model::ml_detection::{AlertMessage, DetectionResult};

const ALERT_CHANNEL_CAPACITY: usize = 100;

pub struct MLAlert  {
    broadcast_tx: broadcast::Sender<AlertMessage>,
}

impl MLAlert {
    pub fn new() -> Self {
        let (broadcast_tx, _) = broadcast::channel(ALERT_CHANNEL_CAPACITY);

        MLAlert {
            broadcast_tx,
        }
    }

    pub fn subscribe_to_alerts(&self) -> broadcast::Receiver<AlertMessage> {
        self.broadcast_tx.subscribe()
    }

    pub fn broadcast_alert(&self, result: &DetectionResult) {
        if self.broadcast_tx.receiver_count() > 0 {
            let alert = AlertMessage::from_detection_result(result);
            if let Err(e) = self.broadcast_tx.send(alert) {
                log!(MLLog::BroadcastAlertFailed(e.to_string()));
            }
        }
    }
}

impl Default for MLAlert {
    fn default() -> Self {
        Self::new()
    }
}
