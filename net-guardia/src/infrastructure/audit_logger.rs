use std::sync::Arc;

use macros::log;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::domain::common::event::{AuditEvent, DriftDetectedEvent};
use crate::domain::common::log::audit::AuditLog;
use crate::interface::audit::AuditRepo;

/// Subscribes to `AuditEvent` and persists each entry to the `audit_log` table.
/// Falls back to log-only when DB writes fail (never panics).
pub struct AuditLogger {
    db: Arc<dyn AuditRepo>,
}

impl AuditLogger {
    pub fn new(db: Arc<dyn AuditRepo>) -> Self {
        Self { db }
    }

    /// Start background tasks that persist audit and drift events to DB + structured logs.
    pub fn start(
        self: Arc<Self>,
        audit_rx: broadcast::Receiver<AuditEvent>,
        drift_rx: broadcast::Receiver<DriftDetectedEvent>,
    ) {
        // Drain AuditEvent receiver
        {
            let this = self.clone();
            let mut rx = audit_rx;
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            this.handle_audit_event(event).await;
                        }
                        Err(RecvError::Lagged(n)) => {
                            log!(AuditLog::AuditLagged(n));
                        }
                        Err(RecvError::Closed) => {
                            log!(AuditLog::AuditChannelClosed);
                            break;
                        }
                    }
                }
            });
        }

        // Drain DriftDetectedEvent receiver — log as audit trail entry
        {
            let this = self;
            let mut rx = drift_rx;
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            this.handle_drift_event(event).await;
                        }
                        Err(RecvError::Lagged(n)) => {
                            log!(AuditLog::AuditLagged(n));
                        }
                        Err(RecvError::Closed) => {
                            log!(AuditLog::AuditChannelClosed);
                            break;
                        }
                    }
                }
            });
        }
    }

    async fn handle_audit_event(&self, event: AuditEvent) {
        // Always emit a structured log line
        log!(AuditLog::AuditEvent(event.actor.clone(), event.action.clone(),));

        if let Err(e) = self
            .db
            .insert_audit_log(&event.actor, &event.action, &event.detail)
            .await
        {
            log!(AuditLog::AuditDbWriteFailed(e.to_string(), event.actor, event.action));
        }
    }

    async fn handle_drift_event(&self, event: DriftDetectedEvent) {
        let detail = serde_json::json!({
            "drifted_features": event.drifted_features,
            "max_deviation": event.max_deviation,
        })
        .to_string();

        log!(AuditLog::AuditDriftEvent(event.drifted_features.len()));

        if let Err(e) = self.db.insert_audit_log("system", "ml_drift_detected", &detail).await {
            log!(AuditLog::AuditDriftDbWriteFailed(e.to_string()));
        }
    }
}
