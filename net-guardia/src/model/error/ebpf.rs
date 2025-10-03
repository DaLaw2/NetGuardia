use macros::traceable;
use tracing;

traceable! {
    EbpfError {
        #[error("Failed to initialize eBPF logger")]
        LoggerInitFailed => tracing::Level::ERROR,

        #[error("Ebpf program not found")]
        EbpfNotFound => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to load XDP program")]
        ProgramNotFound => tracing::Level::ERROR,

        #[error("Failed to load XDP program")]
        GetProgramFailed => tracing::Level::ERROR,

        #[error("Failed to load XDP program")]
        LoadProgramFailed => tracing::Level::ERROR,

        #[error("Failed to attach the XDP program")]
        AttachProgramFailed => tracing::Level::ERROR,

        #[error("Failed to set umem")]
        UmemSetFailed => tracing::Level::ERROR,

        #[error("Failed to set AF_XDP socket")]
        SocketSetFailed => tracing::Level::ERROR,

        #[error("Failed to set AF_XDP")]
        AfXdpSetFailed => tracing::Level::ERROR,

        #[error("Failed to wakeup TX")]
        WakeupTXFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Map not found")]
        MapNotFound => tracing::Level::ERROR,

        #[error("An error occurred during map operation")]
        MapOperationError => tracing::Level::ERROR,

        #[no_source]
        #[error("The ip required for operation does not exist")]
        IpDoesNotExist => tracing::Level::ERROR,

        #[no_source]
        #[error("Amount of rules has reached the upper limit")]
        RuleReachLimit => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown error")]
        UnknownError => tracing::Level::ERROR,
    }
}
