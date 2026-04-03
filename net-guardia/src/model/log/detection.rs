use macros::loggable;
use tracing;

loggable! {
    DetectionLog {
        #[error("Detection orchestrator started")]
        OrchestratorStarted => tracing::Level::INFO,

        #[error("Detection deduplicated: {source_ip} {attack_type} (within window)")]
        DetectionDeduplicated { source_ip: String, attack_type: String } => tracing::Level::DEBUG,

        #[error("Detection emitted: {source_ip} {attack_type} confidence={confidence:.2} sources={sources_count}")]
        DetectionEmitted { source_ip: String, attack_type: String, confidence: f32, sources_count: usize } => tracing::Level::DEBUG,

        #[error("ML detection bridge started")]
        MlBridgeStarted => tracing::Level::INFO,

        #[error("ML detection bridge lagged by {count} events")]
        MlBridgeLagged { count: u64 } => tracing::Level::WARN,

        #[error("ML alert channel closed, detection bridge shutting down")]
        MlAlertChannelClosed => tracing::Level::INFO,

        #[error("Unknown ML attack type '{attack_type}', mapping to 'threat_detected'")]
        UnknownMlAttackType { attack_type: String } => tracing::Level::DEBUG,

        #[error("Correlation engine started")]
        CorrelationEngineStarted => tracing::Level::INFO,

        #[error("Botnet detected: {unique_sources} unique sources → {dst_ip} in {window_secs}s window")]
        BotnetDetected { dst_ip: String, unique_sources: usize, window_secs: u64 } => tracing::Level::WARN,

        #[error("Port scan detected: {src_ip} → {unique_ports} unique ports in {window_secs}s window")]
        ScanDetected { src_ip: String, unique_ports: usize, window_secs: u64 } => tracing::Level::WARN,

        #[error("Lateral movement detected: {src_ip} → {unique_dests} unique internal destinations in {window_secs}s window")]
        LateralMovementDetected { src_ip: String, unique_dests: usize, window_secs: u64 } => tracing::Level::WARN,

        #[error("Beaconing detector started")]
        BeaconingDetectorStarted => tracing::Level::INFO,

        #[error("Beaconing detected: {src_ip} → {dst_ip}:{dst_port} CV={cv:.3} count={count}")]
        BeaconingDetected { src_ip: String, dst_ip: String, dst_port: u16, cv: f64, count: usize } => tracing::Level::WARN,

        #[error("Correlation cleanup: removed {removed} expired entries")]
        CorrelationCleanup { removed: usize } => tracing::Level::DEBUG,
    }
}
