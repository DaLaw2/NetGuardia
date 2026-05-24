use macros::traceable;

traceable! {
    SuricataError {
        #[no_source]
        #[error("Suricata binary not found at '{path}'")]
        BinaryNotFound { path: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Suricata config not found at '{path}'")]
        ConfigNotFound { path: String } => tracing::Level::ERROR,

        #[error("Failed to spawn Suricata subprocess")]
        SpawnFailed => tracing::Level::ERROR,

        #[error("Failed to open eve.json stream at '{path}'")]
        EveOpenFailed { path: String } => tracing::Level::ERROR,
    }
}
