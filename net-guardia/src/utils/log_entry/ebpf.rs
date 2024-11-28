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
}
