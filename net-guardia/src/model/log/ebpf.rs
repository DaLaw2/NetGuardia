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
        TXWakeupFailed {error: String} => tracing::Level::WARN,
    }
}
