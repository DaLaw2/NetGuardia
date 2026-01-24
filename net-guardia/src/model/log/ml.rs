use macros::loggable;
use tracing;

loggable! {
    MLLog {
        #[error("Initializing Machine Learning with inference URL: {url}")]
        Initializing { url: String } => tracing::Level::INFO,

        #[error("Continuing without Machine Learning detection")]
        Skiped => tracing::Level::WARN,

        #[error("Machine Learning detection is disabled (no ml_inference_url configured)")]
        Disabled => tracing::Level::INFO,

        #[error("Machine Learning detection starting")]
        Starting => tracing::Level::INFO,

        #[error("Machine Learning detection ready")]
        Ready => tracing::Level::INFO,

        #[error("Machine Learning detection shutdown")]
        Shutdown => tracing::Level::INFO,

        #[error("Machine Learning channel disconnected")]
        ChannelDisconnected => tracing::Level::WARN,

        #[error("Failed to forward packet: {error}")]
        ForwardPacketFailed { error: String } => tracing::Level::WARN,

        #[error("Attach XDP program success")]
        AttachProgramSuccess => tracing::Level::INFO,

        #[error("Queue initialization incomplete")]
        QueueInitIncomplete => tracing::Level::WARN,

        #[error("Queue refill incomplete")]
        QueueRefillIncomplete => tracing::Level::WARN,

        #[error("No frames submit to queue")]
        NoFrameSubmit => tracing::Level::WARN,

        #[error("Queue pair {queue_id} started successfully")]
        QueuePairStarted { queue_id: u32 } => tracing::Level::INFO,

        #[error("ML models loaded - {info}")]
        ModelsLoaded { info: String } => tracing::Level::INFO,

        #[error("Inference configuration loaded: {features} features, {attacks} attack types")]
        ConfigLoaded { features: usize, attacks: usize } => tracing::Level::INFO,

        #[error("ML Engine started: max_flows={max_flows}, min_packets={min_packets}, interval={interval_secs}s")]
        EngineStarted { max_flows: usize, min_packets: usize, interval_secs: u64 } => tracing::Level::INFO,

        #[error("Inference completed: {total_flows} flows ({malicious} malicious, {benign} benign) in {duration_ms}ms ({throughput:.1} flows/s)")]
        InferenceCompleted { total_flows: usize, malicious: usize, benign: usize, duration_ms: u32, throughput: f32 } => tracing::Level::INFO,

        #[error("Inference skipped: {reason}")]
        InferenceSkipped { reason: String } => tracing::Level::INFO,

        #[error("Threat detected: {flow} -> {attack_type} (confidence: {confidence:.2}, AE error: {ae_error:.4})")]
        ThreatDetected { flow: String, attack_type: String, confidence: f32, ae_error: f32 } => tracing::Level::WARN,

        #[error("Flow stats: total={total_flows}, qualified={flows_len}, min_packets={min_packets}")]
        FlowStats { total_flows: usize,  flows_len: usize, min_packets: usize } => tracing::Level::INFO,

        #[error("Running inference on {size} flows")]
        RunningInference { size: usize } => tracing::Level::INFO,

        #[error("Inference returned fewer results: expected {size}, got {len}")]
        InferenceResults { size: usize, len: usize } => tracing::Level::INFO,

        #[error("{model} inference failed: {error}")]
        InferenceFailed { model: String, error: String } => tracing::Level::INFO,

        #[error("Failed to parse packet (length: {len})")]
        ParsePacketFailed { len: usize } => tracing::Level::INFO,

        #[error("Packet counts: {counts}")]
        PacketCounts { counts: String } => tracing::Level::DEBUG,
    }
}