use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use arc_swap::ArcSwap;
use macros::log;

use crate::common::error::Error;
use crate::common::log::audit::AuditLog;
use crate::common::log::system::SystemLog;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::system::EnforceMode;
use crate::interface::system::audit::AuditRepo;
use crate::interface::system::config_repo::ConfigRepo;

pub const ENFORCE_LEVEL_MONITOR: u8 = 0;
pub const ENFORCE_LEVEL_ML_ONLY: u8 = 1;
pub const ENFORCE_LEVEL_ENFORCE: u8 = 2;

pub fn enforce_mode_to_u8(mode: EnforceMode) -> u8 {
    match mode {
        EnforceMode::Enforce => ENFORCE_LEVEL_ENFORCE,
        EnforceMode::MlOnly => ENFORCE_LEVEL_ML_ONLY,
        EnforceMode::Monitor => ENFORCE_LEVEL_MONITOR,
    }
}

pub struct EnforceModeHandler {
    db: Arc<dyn ConfigRepo>,
    audit_repo: Arc<dyn AuditRepo>,
    app_config: Arc<ArcSwap<AppConfig>>,
    enforce_cache: Arc<AtomicU8>,
}

impl EnforceModeHandler {
    pub fn new(
        db: Arc<dyn ConfigRepo>,
        audit_repo: Arc<dyn AuditRepo>,
        app_config: Arc<ArcSwap<AppConfig>>,
        enforce_cache: Arc<AtomicU8>,
    ) -> Self {
        Self {
            db,
            audit_repo,
            app_config,
            enforce_cache,
        }
    }

    pub async fn change_mode(&self, mode: EnforceMode) -> Result<(), Error> {
        self.db.set_config_value("enforce_mode", mode.as_str()).await?;

        let actor = "admin";
        let action = "enforce_mode_changed";
        let detail = serde_json::json!({ "new_mode": mode.to_string() }).to_string();
        self.audit_repo.insert_audit_log(actor, action, &detail).await?;
        log!(AuditLog::AuditEvent(actor.to_string(), action.to_string()));

        self.enforce_cache.store(enforce_mode_to_u8(mode), Ordering::SeqCst);
        let mut cfg = (**self.app_config.load()).clone();
        cfg.system.enforce_mode = mode;
        self.app_config.store(Arc::new(cfg));
        log!(SystemLog::EnforceModeChanged(mode.to_string()));

        Ok(())
    }

    pub fn get_mode(&self) -> EnforceMode {
        self.app_config.load().system.enforce_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;
    use crate::core::common::config_loader::load_app_config;

    async fn test_handler() -> EnforceModeHandler {
        let db = Arc::new(Database::new(":memory:").await.unwrap());
        let app_config = Arc::new(ArcSwap::from_pointee(load_app_config(db.as_ref()).await.unwrap()));
        let cache = Arc::new(AtomicU8::new(0));
        EnforceModeHandler::new(
            db.clone() as Arc<dyn ConfigRepo>,
            db as Arc<dyn AuditRepo>,
            app_config,
            cache,
        )
    }

    #[tokio::test]
    async fn test_default_mode_is_monitor() {
        let handler = test_handler().await;
        let mode = handler.get_mode();
        assert_eq!(mode, EnforceMode::Monitor);
    }

    #[tokio::test]
    async fn test_change_to_enforce() {
        let handler = test_handler().await;
        handler.change_mode(EnforceMode::Enforce).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, EnforceMode::Enforce);
    }

    #[tokio::test]
    async fn test_change_back_to_monitor() {
        let handler = test_handler().await;
        handler.change_mode(EnforceMode::Enforce).await.unwrap();
        handler.change_mode(EnforceMode::Monitor).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, EnforceMode::Monitor);
    }

    #[tokio::test]
    async fn test_change_to_ml_only() {
        let handler = test_handler().await;
        handler.change_mode(EnforceMode::MlOnly).await.unwrap();
        let mode = handler.get_mode();
        assert_eq!(mode, EnforceMode::MlOnly);
    }

    #[tokio::test]
    async fn test_cycle_all_modes() {
        let handler = test_handler().await;
        for expected in [EnforceMode::Enforce, EnforceMode::MlOnly, EnforceMode::Monitor] {
            handler.change_mode(expected).await.unwrap();
            let mode = handler.get_mode();
            assert_eq!(mode, expected);
        }
    }
}
