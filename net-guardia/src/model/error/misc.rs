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

        #[error("Invalid GeoIP configuration")]
        InvalidGeoIPConfiguration => tracing::Level::ERROR,
    }
}
