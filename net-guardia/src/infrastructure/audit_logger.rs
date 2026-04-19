use std::sync::Arc;

use macros::log;
use tokio::sync::broadcast::error::RecvError;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::interface::port::audit::AuditRepo;
use crate::model::event::{AuditEvent, DriftDetectedEvent};
use crate::model::log::audit::AuditLog;

/// Subscribes to `AuditEvent` and persists each entry to the `audit_log` table.
/// Falls back to log-only when DB writes fail (never panics).
pub struct AuditLogger {
    db: Arc<dyn AuditRepo>,
}

impl AuditLogger {
    pub fn new(db: Arc<dyn AuditRepo>) -> Self {
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
        } else {
            log!(AuditLog::AuditSubscribeFailed);
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
