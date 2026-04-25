use std::sync::Arc;

use macros::log;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::domain::common::event::{AuditEvent, DriftDetectedEvent};
use crate::domain::common::log::audit::AuditLog;
use crate::interface::port::audit::AuditRepo;

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

        // SQLite insert via r2d2 is blocking; offload so it can't stall the
        // tokio worker that drains the broadcast channel. The actor/action
        // strings are cloned for the log call above; the event itself moves
        // into the blocking task.
        let db = self.db.clone();
        let join = tokio::task::spawn_blocking(move || {
            db.insert_audit_log(&event.actor, &event.action, &event.detail)
                .map_err(|e| (e.to_string(), event.actor, event.action))
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err((err, actor, action))) => {
                log!(AuditLog::AuditDbWriteFailed(err, actor, action));
            }
            Err(join_err) => {
                log!(AuditLog::AuditDbWriteFailed(
                    format!("blocking task join failed: {join_err}"),
                    "<lost>".to_string(),
                    "<lost>".to_string(),
                ));
            }
        }
    }

    async fn handle_drift_event(&self, event: DriftDetectedEvent) {
        let detail = serde_json::json!({
            "drifted_features": event.drifted_features,
            "max_deviation": event.max_deviation,
        })
        .to_string();

        log!(AuditLog::AuditDriftEvent(event.drifted_features.len()));

        let db = self.db.clone();
        let join = tokio::task::spawn_blocking(move || {
            db.insert_audit_log("system", "ml_drift_detected", &detail)
                .map_err(|e| e.to_string())
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                log!(AuditLog::AuditDriftDbWriteFailed(err));
            }
            Err(join_err) => {
                log!(AuditLog::AuditDriftDbWriteFailed(format!(
                    "blocking task join failed: {join_err}"
                )));
            }
        }
    }
}
