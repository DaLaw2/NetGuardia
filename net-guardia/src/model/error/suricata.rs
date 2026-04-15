use macros::traceable;
use tracing;

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

        #[no_source]
        #[error("Suricata subprocess exited: {reason}")]
        SubprocessExited { reason: String } => tracing::Level::WARN,

        #[error("Failed to open eve.json stream at '{path}'")]
        EveOpenFailed { path: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Failed to parse eve.json line: {reason}")]
        EveParseFailed { reason: String } => tracing::Level::WARN,
    }
}
