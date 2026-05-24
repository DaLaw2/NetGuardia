use std::sync::Arc;

use macros::log;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use crate::common::log::audit::AuditLog;
use crate::domain::common::event::{AuditEvent, DriftDetectedEvent};
use crate::interface::system::audit::AuditRepo;

pub struct AuditLogger {
    db: Arc<dyn AuditRepo>,
}

impl AuditLogger {
    pub fn new(db: Arc<dyn AuditRepo>) -> Self {
        Self { db }
    }

    pub fn start(
        self: Arc<Self>,
        audit_rx: broadcast::Receiver<AuditEvent>,
        drift_rx: broadcast::Receiver<DriftDetectedEvent>,
    ) -> Vec<(&'static str, JoinHandle<()>)> {
        let mut handles = Vec::with_capacity(2);
        handles.push({
            let this = self.clone();
            let mut rx = audit_rx;
            (
                "audit_logger_audit_events",
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(event) => {
                                this.handle_audit_event(event).await;
                            }
                            Err(RecvError::Lagged(n)) => {
                                log!(AuditLog::AuditLagged("audit".to_string(), n));
                            }
                            Err(RecvError::Closed) => {
                                log!(AuditLog::AuditChannelClosed);
                                break;
                            }
                        }
                    }
                }),
            )
        });

        handles.push({
            let this = self;
            let mut rx = drift_rx;
            (
                "audit_logger_drift_events",
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(event) => {
                                this.handle_drift_event(event).await;
                            }
                            Err(RecvError::Lagged(n)) => {
                                log!(AuditLog::AuditLagged("drift".to_string(), n));
                            }
                            Err(RecvError::Closed) => {
                                log!(AuditLog::AuditChannelClosed);
                                break;
                            }
                        }
                    }
                }),
            )
        });

        handles
    }

    async fn handle_audit_event(&self, event: AuditEvent) {
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
