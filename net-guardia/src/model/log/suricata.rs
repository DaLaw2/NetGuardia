use macros::loggable;
use tracing;

loggable! {
    SuricataLog {
        #[error("Suricata bridge disabled by config")]
        Disabled => tracing::Level::INFO,

        #[error("Spawning Suricata: {binary} -c {config} -i {iface}")]
        Spawning { binary: String, config: String, iface: String } => tracing::Level::INFO,

        #[error("Suricata subprocess started (pid={pid})")]
        Started { pid: u32 } => tracing::Level::INFO,

        #[error("Suricata subprocess exited unexpectedly: {reason}. Restart in {backoff}s")]
        CrashedRestartPending { reason: String, backoff: u64 } => tracing::Level::WARN,

        #[error("Suricata subprocess stopped: {reason}")]
        Stopped { reason: String } => tracing::Level::INFO,

        #[error("Suricata subprocess sent SIGTERM for graceful shutdown")]
        ShutdownRequested => tracing::Level::INFO,

        #[error("Suricata eve.json monitor waiting for file: {path}")]
        MonitorWaitingForFile { path: String } => tracing::Level::INFO,

        #[error("Suricata eve.json monitor attached to {path}")]
        MonitorAttached { path: String } => tracing::Level::INFO,

        #[error("Suricata eve.json rotated — reopening")]
        MonitorFileRotated => tracing::Level::INFO,

        #[error("Suricata alert forwarded: sid={sid} {src}->{dst} {signature}")]
        AlertForwarded { sid: u32, src: String, dst: String, signature: String } => tracing::Level::DEBUG,
    }
}
