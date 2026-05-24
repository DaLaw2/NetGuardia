use macros::log;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::domain::common::event::DetectionEvent;
use crate::domain::detection::log::DetectionLog;

pub mod beaconing;
pub mod metrics;
pub mod orchestrator;

pub fn send_detection_or_log(tx: &mpsc::Sender<DetectionEvent>, event: DetectionEvent) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(dropped) | TrySendError::Closed(dropped)) => {
            log!(DetectionLog::DetectionChannelDrop(
                format!("{:?}", dropped.source),
                dropped.attack_type,
                dropped.source_ip,
            ));
            false
        }
    }
}
