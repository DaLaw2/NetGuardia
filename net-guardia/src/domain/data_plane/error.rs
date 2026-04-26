use macros::traceable;
use tracing;

traceable! {
    EbpfError {
        #[error("Failed to initialize eBPF logger")]
        LoggerInitFailed => tracing::Level::ERROR,

        #[error("eBPF object not found")]
        EbpfNotFound => tracing::Level::ERROR,

        #[no_source]
        #[error("XDP program not found")]
        ProgramNotFound => tracing::Level::ERROR,

        #[error("Failed to get XDP program")]
        GetProgramFailed => tracing::Level::ERROR,

        #[error("Failed to load XDP program")]
        LoadProgramFailed => tracing::Level::ERROR,

        #[error("Failed to attach XDP program")]
        AttachProgramFailed => tracing::Level::ERROR,

        #[error("Failed to obtain eBPF program FD")]
        ProgramFdFailed => tracing::Level::ERROR,

        #[error("Failed to set umem")]
        UmemSetFailed => tracing::Level::ERROR,

        #[error("Failed to set AF_XDP socket")]
        SocketSetFailed => tracing::Level::ERROR,

        #[error("Failed to configure AF_XDP")]
        AfXdpSetFailed => tracing::Level::ERROR,

        #[error("Failed to wakeup TX")]
        WakeupTXFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("eBPF map not found")]
        MapNotFound => tracing::Level::ERROR,

        #[error("eBPF map operation failed")]
        MapOperationError => tracing::Level::ERROR,

        #[no_source]
        #[error("IP does not exist in map")]
        IpDoesNotExist => tracing::Level::ERROR,

        #[no_source]
        #[error("Rule count has reached the upper limit")]
        RuleReachLimit => tracing::Level::ERROR,

        #[no_source]
        #[error("Fill queue initialization failed")]
        FillQueueInitFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid IP address: {ip}")]
        InvalidIpAddress { ip: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("IP version mismatch: expected {expected}")]
        IpVersionMismatch { expected: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown eBPF error")]
        UnknownError => tracing::Level::ERROR,

        #[error("Failed to spawn XSK thread")]
        ThreadSpawnFailed => tracing::Level::ERROR,

        #[error("Completion queue processing failed")]
        CompQueueError => tracing::Level::ERROR,

        #[error("RX queue processing failed")]
        RXQueueError => tracing::Level::ERROR,

        #[error("TX queue processing failed")]
        TXQueueError => tracing::Level::ERROR,

        #[error("eBPF rollback failed during ACL update: {err}")]
        RollbackFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("eBPF data plane is not loaded on this run — operation unavailable")]
        NotLoaded => tracing::Level::WARN,
    }
}
