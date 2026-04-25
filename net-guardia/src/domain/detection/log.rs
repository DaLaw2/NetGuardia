use macros::loggable;
use tracing;

loggable! {
    MLLog {
        #[error("ML models loaded - {info}")]
        ModelsLoaded { info: String } => tracing::Level::INFO,

        #[error("Inference configuration loaded: {features} features, {attacks} attack types")]
        ConfigLoaded { features: usize, attacks: usize } => tracing::Level::INFO,

        #[error("Running inference on {size} flows")]
        RunningInference { size: usize } => tracing::Level::TRACE,

        #[error("Inference completed: {total_flows} flows ({anomaly} anomaly, {benign} benign) in {duration_ms}ms ({throughput:.1} flows/s)")]
        InferenceCompleted { total_flows: usize, anomaly: usize, benign: usize, duration_ms: u32, throughput: f32 } => tracing::Level::TRACE,

        #[error("Inference returned fewer results: expected {size}, got {len}")]
        InferenceResults { size: usize, len: usize } => tracing::Level::DEBUG,

        #[error("{model} inference failed: {error}")]
        InferenceFailed { model: String, error: String } => tracing::Level::ERROR,

        #[error("Threat detected [{direction}]: {flow} -> {attack_type} (confidence: {confidence:.2}, ae_score: {ae_score:.4})")]
        ThreatDetected { direction: String, flow: String, attack_type: String, confidence: f32, ae_score: f32 } => tracing::Level::WARN,

        #[error("Flow stats: total={total_flows}, qualified={flows_len}, min_packets={min_packets}, packet_counts: {counts}")]
        FlowStats { total_flows: usize, flows_len: usize, min_packets: usize, counts: String } => tracing::Level::TRACE,

        #[error("Failed to parse packet (length: {len})")]
        ParsePacketFailed { len: usize } => tracing::Level::DEBUG,

        #[error("Failed to broadcast ML alert: {error}")]
        BroadcastAlertFailed { error: String } => tracing::Level::ERROR,

        #[error("Traffic logger write error: {error}")]
        TrafficLogWriteError { error: String } => tracing::Level::ERROR,

        #[error("Traffic logger channel disconnected")]
        TrafficLogChannelDisconnected => tracing::Level::WARN,

        #[error("Traffic logger dropped a row (channel full — writer thread falling behind)")]
        TrafficLogChannelBackpressure => tracing::Level::WARN,

        #[error("Flow Trace recording stopped: {reason}")]
        FlowTraceStopped { reason: String } => tracing::Level::WARN,

        #[error("ML circuit breaker OPEN: {failures} failures in {window_secs}s, inference disabled until reset")]
        CircuitBreakerOpen { failures: u32, window_secs: u64 } => tracing::Level::ERROR,

        #[error("ML circuit breaker RESET: inference re-enabled after {cooldown_secs}s cooldown")]
        CircuitBreakerReset { cooldown_secs: u64 } => tracing::Level::WARN,

        #[error("Loading ONNX model '{name}' (features={features}, batch_size={batch_size})...")]
        ModelLoading { name: String, features: usize, batch_size: usize } => tracing::Level::INFO,

        #[error("Model '{name}' loaded and optimized in {elapsed_ms}ms")]
        ModelLoadComplete { name: String, elapsed_ms: u64 } => tracing::Level::INFO,

        #[error("Model watcher started, monitoring models/ for .onnx changes")]
        ModelWatcherStarted => tracing::Level::INFO,

        #[error("Model reload triggered, loading new ONNX models...")]
        ModelReloadStarting => tracing::Level::INFO,

        #[error("Model reload successful, inference pipeline updated")]
        ModelReloadSuccess => tracing::Level::INFO,

        #[error("Model reload failed, keeping current models: {error}")]
        ModelReloadFailed { error: String } => tracing::Level::ERROR,

        #[error("Model manifest loaded: name='{name}', adapter={adapter}, features={features}, labels={labels}")]
        ManifestLoaded { name: String, adapter: String, features: usize, labels: usize } => tracing::Level::INFO,

        #[error("ONNX input shape introspected for {model}: declared={declared}, onnx_dim={onnx_dim}, matched={matched}")]
        OnnxShapeChecked { model: String, declared: usize, onnx_dim: usize, matched: bool } => tracing::Level::DEBUG,
    }
}

loggable! {
    DetectionLog {
        #[error("Detection orchestrator started")]
        OrchestratorStarted => tracing::Level::INFO,

        #[error("Detection deduplicated: {source_ip} {attack_type} (within window)")]
        DetectionDeduplicated { source_ip: String, attack_type: String } => tracing::Level::DEBUG,

        #[error("Detection emitted: {source_ip} {attack_type} confidence={confidence:.2} ae={ae_score:.3} anomaly={anomaly_score:.3} c2={c2_score:.3} sources={sources_count}")]
        DetectionEmitted { source_ip: String, attack_type: String, confidence: f32, ae_score: f32, anomaly_score: f32, c2_score: f32, sources_count: usize } => tracing::Level::DEBUG,

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

        #[error("Fusion: emitted {source_ip} {attack_type} fused={fused:.3} sources={count}")]
        FusionEmitted { source_ip: String, attack_type: String, fused: f32, count: usize } => tracing::Level::DEBUG,

        #[error("Fusion: window evicted under LRU pressure ({key_src} {key_type})")]
        FusionWindowEvicted { key_src: String, key_type: String } => tracing::Level::WARN,

        #[error("Detection event dropped (channel full): {detector} {attack_type} from {source_ip}")]
        DetectionChannelDrop { detector: String, attack_type: String, source_ip: String } => tracing::Level::WARN,
    }
}

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
