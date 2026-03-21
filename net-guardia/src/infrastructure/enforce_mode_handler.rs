use async_trait::async_trait;
use std::sync::Arc;

use crate::interface::communication::command::CommandHandler;
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query::QueryHandler;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::repository::RepositoryPort;
use crate::model::error::Error;

/// Handles enforce-mode commands and queries by delegating to the repository.
pub struct EnforceModeHandler {
    db: Arc<dyn RepositoryPort>,
}

impl EnforceModeHandler {
    pub fn new(db: Arc<dyn RepositoryPort>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl CommandHandler<ChangeEnforceModeCommand> for EnforceModeHandler {
    async fn handle_command(&self, command: ChangeEnforceModeCommand) -> Result<(), Error> {
        self.db.set_setting("enforce_mode", &command.mode)?;
        tracing::info!("Enforce mode changed to: {}", command.mode);
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
        let db = Arc::new(Database::new(":memory:").unwrap()) as Arc<dyn RepositoryPort>;
        let handler = Arc::new(EnforceModeHandler::new(db));
        let comm = Arc::new(CommunicationManager::new());
        let _ = comm.clone()
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
        comm.send_command(ChangeEnforceModeCommand { mode: "enforce".into() }).await.unwrap();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "enforce");
    }

    #[tokio::test]
    async fn test_change_back_to_monitor() {
        let (_, comm) = test_handler();
        comm.send_command(ChangeEnforceModeCommand { mode: "enforce".into() }).await.unwrap();
        comm.send_command(ChangeEnforceModeCommand { mode: "monitor".into() }).await.unwrap();
        let mode = comm.send_query(GetEnforceModeQuery).await.unwrap();
        assert_eq!(mode, "monitor");
    }
}
