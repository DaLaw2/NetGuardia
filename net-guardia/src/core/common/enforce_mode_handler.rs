use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::broadcast;

use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::enforce_mode_to_u8;
use crate::domain::common::error::Error;
use crate::domain::common::event::AuditEvent;
use crate::domain::common::log::system::SystemLog;
use crate::interface::app_repo::AppRepo;

/// Handles enforce-mode commands and queries by delegating to the repository.
pub struct EnforceModeHandler {
    db: Arc<dyn AppRepo>,
    app_config: Arc<ArcSwap<AppConfig>>,
    audit_tx: broadcast::Sender<AuditEvent>,
    /// Shared AtomicU8 cache: Monitor=0, MlOnly=1, Enforce=2.
    enforce_cache: Arc<AtomicU8>,
}

impl EnforceModeHandler {
    pub fn new(
        db: Arc<dyn AppRepo>,
        app_config: Arc<ArcSwap<AppConfig>>,
        audit_tx: broadcast::Sender<AuditEvent>,
        enforce_cache: Arc<AtomicU8>,
    ) -> Self {
        Self {
            db,
            app_config,
            audit_tx,
            enforce_cache,
        }
    }

    pub async fn change_mode(&self, mode: String) -> Result<(), Error> {
        self.db.set_config_value("enforce_mode", &mode).await?;
        self.enforce_cache.store(enforce_mode_to_u8(&mode), Ordering::SeqCst);
        let mut cfg = (**self.app_config.load()).clone();
        cfg.system.enforce_mode = mode.clone();
        self.app_config.store(Arc::new(cfg));
        log!(SystemLog::EnforceModeChanged(mode.clone()));

        // Publish audit event for the mode change
        let _ = self.audit_tx.send(AuditEvent {
            actor: "admin".to_string(),
            action: "enforce_mode_changed".to_string(),
            detail: serde_json::json!({ "new_mode": mode }).to_string(),
        });

        Ok(())
    }

    pub fn get_mode(&self) -> String {
        self.app_config.load().system.enforce_mode.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;
    use crate::domain::common::config::constants::EVENT_CHANNEL_CAPACITY;

    async fn test_handler() -> EnforceModeHandler {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let app_config = Arc::new(ArcSwap::from_pointee(
            AppConfig::from_config_repo(db.as_ref()).await.unwrap(),
        ));
        let cache = Arc::new(AtomicU8::new(0));
        let (audit_tx, _rx) = broadcast::channel::<AuditEvent>(EVENT_CHANNEL_CAPACITY);
        EnforceModeHandler::new(db as Arc<dyn AppRepo>, app_config, audit_tx, cache)
    }

    #[tokio::test]
    async fn test_default_mode_is_monitor() {
        let handler = test_handler().await;
        let mode = handler.get_mode();
        assert_eq!(mode, "monitor");
    }

    #[tokio::test]
    async fn test_change_to_enforce() {
        let handler = test_handler().await;
        handler.change_mode("enforce".into()).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, "enforce");
    }

    #[tokio::test]
    async fn test_change_back_to_monitor() {
        let handler = test_handler().await;
        handler.change_mode("enforce".into()).await.unwrap();
        handler.change_mode("monitor".into()).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, "monitor");
    }

    #[tokio::test]
    async fn test_change_to_ml_only() {
        let handler = test_handler().await;
        handler.change_mode("ml_only".into()).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, "ml_only");
    }

    #[tokio::test]
    async fn test_cycle_all_modes() {
        let handler = test_handler().await;
        for mode_str in ["enforce", "ml_only", "monitor"] {
            handler.change_mode(mode_str.into()).await.unwrap();
            let mode = handler.get_mode();
            assert_eq!(mode, mode_str);
        }
    }
}
