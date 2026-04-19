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
