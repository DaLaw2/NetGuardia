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
    }
}
