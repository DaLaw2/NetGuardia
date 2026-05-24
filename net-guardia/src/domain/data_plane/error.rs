use macros::traceable;

use crate::domain::data_plane::direction::Direction;

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

        #[no_source]
        #[error("Failed to remove limit on locked memory, ret is: {ret}")]
        MemoryLimitUnlockFailed { ret: i32 } => tracing::Level::ERROR,

        #[error("Failed to wakeup TX")]
        WakeupTXFailed => tracing::Level::ERROR,

        #[no_source]
        #[error("eBPF map not found")]
        MapNotFound => tracing::Level::ERROR,

        #[error("eBPF map operation failed: {err}")]
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
        #[error("Fill queue initialization incomplete: produced {produced}, expected {expected}")]
        FillQueueInitIncomplete { produced: usize, expected: usize } => tracing::Level::ERROR,

        #[no_source]
        #[error("AF_XDP queue unavailable for {direction} queue {queue_id}")]
        AfXdpQueueUnavailable { direction: Direction, queue_id: u32 } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid IP address: {ip}")]
        InvalidIpAddress { ip: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid DNS domain: {message}")]
        InvalidDnsDomain { message: String } => tracing::Level::WARN,

        #[no_source]
        #[error("DNS label length out of range: {len} (must be 1..64)")]
        DnsLabelOutOfRange { len: usize } => tracing::Level::WARN,

        #[no_source]
        #[error("DNS domain name too long: '{domain}'")]
        DnsDomainTooLong { domain: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Too many DNS domains in one request (max {max})")]
        TooManyDnsDomains { max: usize } => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid rate limit value for {field}: {value} (must be greater than 0)")]
        InvalidRateLimitValue { field: String, value: u64 } => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid country code: {code}")]
        InvalidCountryCode { code: String } => tracing::Level::WARN,

        #[error("Invalid GeoIP CIDR literal '{cidr}': {err}")]
        InvalidGeoIpCidr { cidr: String } => tracing::Level::ERROR,

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
