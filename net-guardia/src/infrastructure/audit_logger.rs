use std::sync::Arc;

use macros::log;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::interface::port::audit::AuditPort;
use crate::model::event::{AuditEvent, DriftDetectedEvent};
use crate::model::log::audit::AuditLog;

/// Subscribes to `AuditEvent` and persists each entry to the `audit_log` table.
/// Falls back to log-only when DB writes fail (never panics).
pub struct AuditLogger {
    db: Arc<dyn AuditPort>,
}

impl AuditLogger {
    pub fn new(db: Arc<dyn AuditPort>) -> Self {
        Self { db }
    }

    /// Subscribe to AuditEvent and DriftDetectedEvent on the communication manager
    /// and start background tasks that persist events to DB + structured logs.
    pub fn start(self: Arc<Self>, comm: &CommunicationManager) {
        // Subscribe to AuditEvent
        if let Ok(mut rx) = comm.subscribe_event::<AuditEvent>() {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            this.handle_audit_event(&event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            log!(AuditLog::AuditLagged { count: n });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log!(AuditLog::AuditChannelClosed);
                            break;
                        }
                    }
                }
            });
        } else {
            log!(AuditLog::AuditSubscribeFailed);
        }

        // Subscribe to DriftDetectedEvent — log as audit trail entry
        if let Ok(mut rx) = comm.subscribe_event::<DriftDetectedEvent>() {
            let this = self;
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            this.handle_drift_event(&event);
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            log!(AuditLog::AuditLagged { count: n });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            log!(AuditLog::AuditChannelClosed);
                            break;
                        }
                    }
                }
            });
        } else {
            log!(AuditLog::AuditSubscribeFailed);
        }
    }

    fn handle_audit_event(&self, event: &AuditEvent) {
        // Always emit a structured log line
        log!(AuditLog::AuditEvent {
            actor: event.actor.clone(),
            action: event.action.clone()
        });

        // Attempt DB insert; on failure, log a warning but do not panic
        if let Err(e) = self.db.insert_audit_log(&event.actor, &event.action, &event.detail) {
            log!(AuditLog::AuditDbWriteFailed {
                error: e.to_string(),
                actor: event.actor.clone(),
                action: event.action.clone()
            });
        }
    }

    fn handle_drift_event(&self, event: &DriftDetectedEvent) {
        let detail = serde_json::json!({
            "drifted_features": event.drifted_features,
            "max_deviation": event.max_deviation,
        })
        .to_string();

        log!(AuditLog::AuditDriftEvent {
            count: event.drifted_features.len()
        });

        if let Err(e) = self.db.insert_audit_log("system", "ml_drift_detected", &detail) {
            log!(AuditLog::AuditDriftDbWriteFailed { error: e.to_string() });
        }
    }
}
