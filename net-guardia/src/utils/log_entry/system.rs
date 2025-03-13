use thiserror::Error;

#[derive(Error, Debug)]
pub enum SystemEntry {
    #[error("Online now")]
    Online,
    #[error("Initializing")]
    Initializing,
    #[error("Initialization completed")]
    InitializeComplete,
    #[error("Termination in process")]
    Terminating,
    #[error("Termination completed")]
    TerminateComplete,
    #[error("Invalid configuration")]
    InvalidConfig,
    #[error("Configuration not found")]
    ConfigNotFound,
    #[error("Invalid alert {0}")]
    InvalidAlert(String),
    #[error("Failed to clear alert file")]
    ClearAlertFailed,
}
