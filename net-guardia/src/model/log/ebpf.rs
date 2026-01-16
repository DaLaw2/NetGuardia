use macros::loggable;
use tracing;

loggable! {
    EbpfLog {
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

        #[error("XSK thread shutting down")]
        XSKShutdown => tracing::Level::INFO,

        #[error("Frame pool exhausted! Pending TX: {send_len} packets")]
        FramePoolExhausted { send_len: usize } => tracing::Level::WARN,

        #[error("No frames available for TX")]
        NoFramesAvailable => tracing::Level::WARN,
        
        #[error("TX wakeup failed: {error}")]
        TXWakeupFailed { error: String } => tracing::Level::WARN,

        #[error("Completion queue processing error: {error}")]
        CompQueueError { error: String } => tracing::Level::ERROR,

        #[error("RX queue processing error: {error}")]
        RXQueueError { error: String } => tracing::Level::ERROR,

        #[error("TX queue processing error: {error}")]
        TXQueueError { error: String } => tracing::Level::ERROR,

        #[error("Failed to spawn thread '{thread_name}': {error}")]
        ThreadSpawnFailed { thread_name: String, error: String } => tracing::Level::ERROR,

        #[error("Forward channel full, dropping packet")]
        ForwardChannelFull => tracing::Level::WARN,

        #[error("Forward channel disconnected")]
        ForwardChannelDisconnected => tracing::Level::ERROR,

        #[error("Fill queue incomplete: produced {produced}, expected {expected}")]
        FillQueueIncomplete { produced: usize, expected: usize } => tracing::Level::WARN,
    }
}