use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use macros::log;
use tokio::sync::broadcast;

use crate::domain::common::config::constants::{ENFORCE_MODE_MONITOR, enforce_mode_to_u8};
use crate::domain::common::error::Error;
use crate::domain::common::event::AuditEvent;
use crate::domain::common::log::system::SystemLog;
use crate::interface::app_repo::AppRepo;

/// Handles enforce-mode commands and queries by delegating to the repository.
pub struct EnforceModeHandler {
    db: Arc<dyn AppRepo>,
    audit_tx: broadcast::Sender<AuditEvent>,
    /// Shared AtomicU8 cache: Monitor=0, MlOnly=1, Enforce=2.
    enforce_cache: Arc<AtomicU8>,
}

impl EnforceModeHandler {
    pub fn new(db: Arc<dyn AppRepo>, audit_tx: broadcast::Sender<AuditEvent>, enforce_cache: Arc<AtomicU8>) -> Self {
        Self {
            db,
            audit_tx,
            enforce_cache,
        }
    }

    pub fn change_mode(&self, mode: String) -> Result<(), Error> {
        self.db.set_setting("enforce_mode", &mode)?;
        self.enforce_cache.store(enforce_mode_to_u8(&mode), Ordering::SeqCst);
        log!(SystemLog::EnforceModeChanged(mode.clone()));

        // Publish audit event for the mode change
        let _ = self.audit_tx.send(AuditEvent {
            actor: "admin".to_string(),
            action: "enforce_mode_changed".to_string(),
            detail: serde_json::json!({ "new_mode": mode }).to_string(),
        });

        Ok(())
    }

    pub fn get_mode(&self) -> Result<String, Error> {
        match self.db.get_setting("enforce_mode")? {
            Some(mode) => Ok(mode),
            None => Ok(ENFORCE_MODE_MONITOR.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;
    use crate::domain::common::config::constants::EVENT_CHANNEL_CAPACITY;

    fn test_handler() -> EnforceModeHandler {
        let db = Arc::new(Database::new(":memory:").unwrap()) as Arc<dyn AppRepo>;
        let cache = Arc::new(AtomicU8::new(0));
        let (audit_tx, _rx) = broadcast::channel::<AuditEvent>(EVENT_CHANNEL_CAPACITY);
        EnforceModeHandler::new(db, audit_tx, cache)
    }

    #[test]
    fn test_default_mode_is_monitor() {
        let handler = test_handler();
        let mode = handler.get_mode().unwrap();
        assert_eq!(mode, "monitor");
    }

    #[test]
    fn test_change_to_enforce() {
        let handler = test_handler();
        handler.change_mode("enforce".into()).unwrap();
        let mode = handler.get_mode().unwrap();
        assert_eq!(mode, "enforce");
    }

    #[test]
    fn test_change_back_to_monitor() {
        let handler = test_handler();
        handler.change_mode("enforce".into()).unwrap();
        handler.change_mode("monitor".into()).unwrap();
        let mode = handler.get_mode().unwrap();
        assert_eq!(mode, "monitor");
    }

    #[test]
    fn test_change_to_ml_only() {
        let handler = test_handler();
        handler.change_mode("ml_only".into()).unwrap();
        let mode = handler.get_mode().unwrap();
        assert_eq!(mode, "ml_only");
    }

    #[test]
    fn test_cycle_all_modes() {
        let handler = test_handler();
        for mode_str in ["enforce", "ml_only", "monitor"] {
            handler.change_mode(mode_str.into()).unwrap();
            let mode = handler.get_mode().unwrap();
            assert_eq!(mode, mode_str);
        }
    }
}
