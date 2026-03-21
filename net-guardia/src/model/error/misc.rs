use macros::traceable;

traceable! {
    MiscError {
        #[no_source]
        #[error("Failed to remove limit on locked memory, ret is: {ret}")]
        RamLimitUnlockError { ret: i32 } => tracing::Level::ERROR,

        #[error("Failed to send message to receiver")]
        SendMessageError => tracing::Level::ERROR,

        #[error("Failed to serialize data")]
        SerializeError => tracing::Level::ERROR,

        #[error("Failed to deserialize data")]
        DeserializeError => tracing::Level::ERROR,

        #[no_source]
        #[error("Network interface '{interface}' not found")]
        NetworkInterfaceNotFound { interface: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to open GeoIP database '{path}': {reason}")]
        GeoIPDatabaseError { path: String, reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to create traffic log file '{path}': {reason}")]
        TrafficLogCreateError { path: String, reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Invalid DNS domain name: {reason}")]
        InvalidDnsName { reason: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Type mismatch during message dispatch")]
        TypeMismatch => tracing::Level::ERROR,

        #[no_source]
        #[error("No handler registered for this message type")]
        HandlerNotFound => tracing::Level::ERROR,

        #[no_source]
        #[error("Event type not registered with communication manager")]
        TypeNotRegistered => tracing::Level::ERROR,
    }
}
