use super::inference_client::DetectionResult;
use super::flow_record::FlowRecord;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Alert severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Determine severity from confidence score
    pub fn from_confidence(confidence: f64) -> Self {
        if confidence >= 0.9 {
            Severity::Critical
        } else if confidence >= 0.75 {
            Severity::High
        } else if confidence >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// Network intrusion alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: u64,

    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,

    /// Flow information
    pub flow_id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,

    /// Detection information
    pub attack_type: String,
    pub confidence: f64,
    pub mse: f64,
    pub threshold: f64,

    /// Severity
    pub severity: Severity,

    /// Flow statistics
    pub flow_duration_us: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub fwd_packets: u64,
    pub bwd_packets: u64,

    /// Additional context
    pub attack_probabilities: Option<std::collections::HashMap<String, f64>>,

    /// Status
    pub acknowledged: bool,
}

impl Alert {
    /// Create a new alert from detection result and flow
    pub fn new(
        id: u64,
        result: &DetectionResult,
        flow: &FlowRecord,
    ) -> Self {
        let attack_type = result
            .attack_type
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let confidence = result.confidence.unwrap_or(0.0);
        let severity = Severity::from_confidence(confidence);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            id,
            timestamp,
            flow_id: flow.flow_id.clone(),
            src_ip: flow.src_ip.to_string(),
            dst_ip: flow.dst_ip.to_string(),
            src_port: flow.src_port,
            dst_port: flow.dst_port,
            protocol: flow.protocol,
            attack_type,
            confidence,
            mse: result.mse,
            threshold: result.threshold,
            severity,
            flow_duration_us: flow.duration(),
            total_packets: flow.forward.packets + flow.backward.packets,
            total_bytes: flow.forward.bytes + flow.backward.bytes,
            fwd_packets: flow.forward.packets,
            bwd_packets: flow.backward.packets,
            attack_probabilities: result.attack_probabilities.clone(),
            acknowledged: false,
        }
    }
}

/// Alert statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: u64,
    pub alerts_by_severity: std::collections::HashMap<String, u64>,
    pub alerts_by_type: std::collections::HashMap<String, u64>,
    pub recent_alert_rate: f64, // alerts per minute
}

/// Alert manager - manages alerts and notifications
pub struct AlertManager {
    /// Next alert ID
    next_id: Arc<RwLock<u64>>,

    /// Recent alerts (circular buffer)
    recent_alerts: Arc<RwLock<VecDeque<Alert>>>,

    /// Maximum recent alerts to keep
    max_recent_alerts: usize,

    /// Alert callbacks
    callbacks: Arc<RwLock<Vec<Arc<dyn Fn(&Alert) + Send + Sync>>>>,

    /// Statistics
    stats: Arc<RwLock<AlertStats>>,
}

impl AlertManager {
    /// Create a new alert manager
    pub fn new(max_recent_alerts: usize) -> Self {
        Self {
            next_id: Arc::new(RwLock::new(1)),
            recent_alerts: Arc::new(RwLock::new(VecDeque::with_capacity(max_recent_alerts))),
            max_recent_alerts,
            callbacks: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(AlertStats {
                total_alerts: 0,
                alerts_by_severity: std::collections::HashMap::new(),
                alerts_by_type: std::collections::HashMap::new(),
                recent_alert_rate: 0.0,
            })),
        }
    }

    /// Process detection result and create alert if anomaly
    pub fn process_detection(
        &self,
        result: &DetectionResult,
        flow: &FlowRecord,
    ) -> Option<Alert> {
        if !result.is_anomaly {
            return None;
        }

        // Get next ID
        let id = {
            let mut next_id = self.next_id.write();
            let id = *next_id;
            *next_id += 1;
            id
        };

        // Create alert
        let alert = Alert::new(id, result, flow);

        // Store in recent alerts
        {
            let mut recent = self.recent_alerts.write();
            if recent.len() >= self.max_recent_alerts {
                recent.pop_front();
            }
            recent.push_back(alert.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_alerts += 1;

            let severity_key = format!("{:?}", alert.severity).to_lowercase();
            *stats.alerts_by_severity.entry(severity_key).or_insert(0) += 1;

            *stats
                .alerts_by_type
                .entry(alert.attack_type.clone())
                .or_insert(0) += 1;

            // Calculate recent alert rate (alerts in last minute)
            let recent = self.recent_alerts.read();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let one_minute_ago = now.saturating_sub(60_000);
            let recent_count = recent
                .iter()
                .filter(|a| a.timestamp >= one_minute_ago)
                .count();

            stats.recent_alert_rate = recent_count as f64 / 1.0; // per minute
        }

        // Trigger callbacks
        {
            let callbacks = self.callbacks.read();
            for callback in callbacks.iter() {
                callback(&alert);
            }
        }

        tracing::warn!(
            "⚠️  Alert #{}: {} attack detected from {}:{} -> {}:{} (confidence: {:.2}%)",
            alert.id,
            alert.attack_type,
            alert.src_ip,
            alert.src_port,
            alert.dst_ip,
            alert.dst_port,
            alert.confidence * 100.0
        );

        Some(alert)
    }

    /// Register alert callback
    pub fn on_alert<F>(&self, callback: F)
    where
        F: Fn(&Alert) + Send + Sync + 'static,
    {
        self.callbacks.write().push(Arc::new(callback));
    }

    /// Get recent alerts
    pub fn get_recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.recent_alerts.read();
        alerts
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get alert by ID
    pub fn get_alert(&self, id: u64) -> Option<Alert> {
        let alerts = self.recent_alerts.read();
        alerts.iter().find(|a| a.id == id).cloned()
    }

    /// Acknowledge alert
    pub fn acknowledge_alert(&self, id: u64) -> bool {
        let mut alerts = self.recent_alerts.write();
        if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> AlertStats {
        self.stats.read().clone()
    }

    /// Clear all alerts
    pub fn clear_alerts(&self) {
        self.recent_alerts.write().clear();
    }

    /// Get alert count
    pub fn alert_count(&self) -> usize {
        self.recent_alerts.read().len()
    }

    /// Get alerts by severity
    pub fn get_alerts_by_severity(&self, severity: Severity) -> Vec<Alert> {
        let alerts = self.recent_alerts.read();
        alerts
            .iter()
            .filter(|a| a.severity == severity)
            .cloned()
            .collect()
    }

    /// Get alerts by attack type
    pub fn get_alerts_by_type(&self, attack_type: &str) -> Vec<Alert> {
        let alerts = self.recent_alerts.read();
        alerts
            .iter()
            .filter(|a| a.attack_type == attack_type)
            .cloned()
            .collect()
    }
}