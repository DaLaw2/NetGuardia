use macros::loggable;
use tracing;

loggable! {
    SystemLog {
        #[error("Initializing")]
        Initializing => tracing::Level::INFO,

        #[error("Initialization completed")]
        InitializeComplete => tracing::Level::INFO,

        #[error("Termination in process")]
        Terminating => tracing::Level::INFO,

        #[error("Termination completed")]
        TerminateComplete => tracing::Level::INFO,

        #[error("Setup not complete — running in setup mode")]
        SetupMode => tracing::Level::INFO,

        #[error("Setup token: {token}")]
        SetupTokenGenerated { token: String } => tracing::Level::INFO,

        #[error("Setup wizard completed — starting full system initialization")]
        SetupCompleted => tracing::Level::INFO,

        #[error("Full system initialization complete — all services running")]
        FullInitComplete => tracing::Level::INFO,

        #[error("Default admin user created with password 'admin' — password will be set during setup wizard")]
        DefaultAdminCreated => tracing::Level::INFO,

        #[error("Shutdown signal received during setup mode")]
        ShutdownDuringSetup => tracing::Level::INFO,

        #[error("Setup server stopped, starting full system...")]
        SetupServerStopped => tracing::Level::INFO,

        #[error("Enforce mode changed to: {mode}")]
        EnforceModeChanged { mode: String } => tracing::Level::INFO,

        #[error("Triggered shutdown initiated")]
        Shutdown => tracing::Level::INFO,

        #[error("Triggered restart initiated — self-reexecuting")]
        Restart => tracing::Level::INFO,

        #[error("Failed to resolve current executable for restart; falling back to net-guardia: {error}")]
        RestartExecutableLookupFailed { error: String } => tracing::Level::WARN,

        #[error("systemd notify failed for {state}: {error}")]
        SystemdNotifyFailed { state: String, error: String } => tracing::Level::WARN,

        #[error("Security engine unavailable — continuing without data plane")]
        EbpfBringupFailed => tracing::Level::ERROR,
    }
}
