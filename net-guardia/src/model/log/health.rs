use macros::loggable;

loggable! {
    Health {
        #[error("{ifname} interface '{interface}' not found")]
        InterfaceNotFound { ifname: String, interface: String } => tracing::Level::WARN,

        #[error("Failed to broadcast system health metrics: {error}")]
        BroadcastFailed { error: String } => tracing::Level::ERROR,
    }
}
