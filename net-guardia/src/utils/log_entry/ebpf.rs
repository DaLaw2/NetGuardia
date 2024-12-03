use aya::maps::MapError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EbpfEntry {
    #[error("Initializing")]
    Initializing,
    #[error("Initialization completed")]
    InitializeComplete,
    #[error("Failed to initialize eBPF logger")]
    LoggerInitializeFailed,
    #[error("Attach XDP program success")]
    AttachProgramSuccess,
    #[error("Failed to attach the XDP program")]
    AttachProgramFailed,
    #[error("An error occurred while map operation")]
    MapOperationError,
    #[error("Amount of rules has reached the upper limit")]
    RuleReachLimit,
}

impl From<MapError> for EbpfEntry {
    fn from(value: MapError) -> Self {
        match value {
            MapError::OutOfBounds { .. } => EbpfEntry::RuleReachLimit,
            _ => EbpfEntry::MapOperationError
        }
    }
}
