use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use macros::log;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::interface::communication::command::CommandHandler;
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query::QueryHandler;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::app_repo::AppRepo;
use crate::model::error::Error;
use crate::model::event::AuditEvent;
use crate::model::log::system::SystemLog;

/// Map enforce-mode string to u8: monitor=0, ml_only=1, enforce=2.
pub fn enforce_mode_to_u8(mode: &str) -> u8 {
    match mode {
        "enforce" => 2,
        "ml_only" => 1,
        _ => 0, // "monitor" or unknown → safest default
    }
}

/// Handles enforce-mode commands and queries by delegating to the repository.
pub struct EnforceModeHandler {
    db: Arc<dyn AppRepo>,
    comm: Arc<CommunicationManager>,
    /// Shared AtomicU8 cache: Monitor=0, MlOnly=1, Enforce=2.
    enforce_cache: Arc<AtomicU8>,
}

impl EnforceModeHandler {
    pub fn new(db: Arc<dyn AppRepo>, comm: Arc<CommunicationManager>, enforce_cache: Arc<AtomicU8>) -> Self {
        Self {
            db,
            comm,
            enforce_cache,
        }
    }
}

#[async_trait]
impl CommandHandler<ChangeEnforceModeCommand> for EnforceModeHandler {
    async fn handle_command(&self, command: ChangeEnforceModeCommand) -> Result<(), Error> {
        self.db.set_setting("enforce_mode", &command.mode)?;
        self.enforce_cache
            .store(enforce_mode_to_u8(&command.mode), Ordering::SeqCst);
        log!(SystemLog::EnforceModeChanged(command.mode.clone()));

        // Publish audit event for the mode change
        let _ = self
            .comm
            .publish_event(AuditEvent {
                actor: "admin".to_string(),
                action: "enforce_mode_changed".to_string(),
                detail: serde_json::json!({ "new_mode": command.mode }).to_string(),
            })
            .await;

        Ok(())
    }
}

#[async_trait]
impl QueryHandler<GetEnforceModeQuery> for EnforceModeHandler {
    async fn handle_query(&self, _query: GetEnforceModeQuery) -> Result<String, Error> {
        match self.db.get_setting("enforce_mode")? {
            Some(mode) => Ok(mode),
            None => Ok("monitor".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;
    use crate::infrastructure::communication_manager::CommunicationManager;
    use crate::interface::communication::command_types::ChangeEnforceModeCommand;
    use crate::interface::communication::query_types::GetEnforceModeQuery;

    fn test_handler() -> (Arc<EnforceModeHandler>, Arc<CommunicationManager>) {
        let db = Arc::new(Database::new(":memory:").unwrap()) as Arc<dyn AppRepo>;
        let cache = Arc::new(AtomicU8::new(0));
        let comm = Arc::new(CommunicationManager::new());
        comm.register_event_type::<AuditEvent>();
        let handler = Arc::new(EnforceModeHandler::new(db, comm.clone(), cache));
        let _ = comm
            .clone()
            .with_service(handler.clone())
            .command::<ChangeEnforceModeCommand>()
            .query::<GetEnforceModeQuery>()
            .build();
        (handler, comm)
    }

    #[tokio::test]
    async fn test_default_mode_is_monitor() {
        let (_, comm) = test_handler();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "monitor");
    }

    #[tokio::test]
    async fn test_change_to_enforce() {
        let (_, comm) = test_handler();
        comm.send_command(ChangeEnforceModeCommand { mode: "enforce".into() })
            .await
            .unwrap();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "enforce");
    }

    #[tokio::test]
    async fn test_change_back_to_monitor() {
        let (_, comm) = test_handler();
        comm.send_command(ChangeEnforceModeCommand { mode: "enforce".into() })
            .await
            .unwrap();
        comm.send_command(ChangeEnforceModeCommand { mode: "monitor".into() })
            .await
            .unwrap();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "monitor");
    }

    #[tokio::test]
    async fn test_change_to_ml_only() {
        let (_, comm) = test_handler();
        comm.send_command(ChangeEnforceModeCommand { mode: "ml_only".into() })
            .await
            .unwrap();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "ml_only");
    }

    #[tokio::test]
    async fn test_cycle_all_modes() {
        let (_, comm) = test_handler();
        for mode_str in ["enforce", "ml_only", "monitor"] {
            comm.send_command(ChangeEnforceModeCommand { mode: mode_str.into() })
                .await
                .unwrap();
            let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
            assert_eq!(mode, mode_str);
        }
    }
}
