use serde::Serialize;
use tokio::sync::broadcast;
use tracing::error;

use crate::model::ml_detection::DetectionResult;

const ALERT_CHANNEL_CAPACITY: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct AlertMessage {
    pub timestamp: u64,
    pub flow_key: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub is_attack: bool,
    pub attack_type: Option<String>,
    pub confidence: f32,
    pub ae_score: f32,
}

impl AlertMessage {
    pub fn from_detection_result(result: &DetectionResult) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            timestamp,
            flow_key: result.flow_key.clone(),
            src_ip: result.flow_key_raw.src_ip_string(),
            dst_ip: result.flow_key_raw.dst_ip_string(),
            src_port: result.flow_key_raw.src_port,
            dst_port: result.flow_key_raw.dst_port,
            protocol: result.flow_key_raw.protocol,
            is_attack: result.is_attack,
            attack_type: result.attack_type.clone(),
            confidence: result.confidence,
            ae_score: result.ae_score,
        }
    }
}

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
                error!("Failed to broadcast ML alert: {}", e);
            }
        }
    }

}

impl Default for MLAlert {
    fn default() -> Self {
        Self::new()
    }
}