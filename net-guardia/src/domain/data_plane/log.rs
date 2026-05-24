use macros::loggable;
use tracing;

loggable! {
    EbpfLog {
        #[error("Attach XDP program success")]
        AttachProgramSuccess => tracing::Level::INFO,

        #[error("Queue pair {queue_id} started successfully")]
        QueuePairStarted { queue_id: u32 } => tracing::Level::INFO,

        #[error("XSK thread shutting down")]
        XSKShutdown => tracing::Level::INFO,

        #[error("Frame pool exhausted! Pending TX: {send_len} packets")]
        FramePoolExhausted { send_len: usize } => tracing::Level::DEBUG,

        #[error("No frames available for TX")]
        NoFramesAvailable => tracing::Level::DEBUG,

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
        ForwardChannelFull => tracing::Level::DEBUG,

        #[error("Forward channel disconnected")]
        ForwardChannelDisconnected => tracing::Level::ERROR,

        #[error("Drop event broadcast failed: {error}")]
        DropBroadcastFailed { error: String } => tracing::Level::WARN,

        #[error("Fill queue incomplete: produced {produced}, expected {expected}")]
        FillQueueIncomplete { produced: usize, expected: usize } => tracing::Level::WARN,

        #[error("Invalid packet length exceeds buffer")]
        InvalidPacketLength => tracing::Level::DEBUG,

        #[error("XDP attached to {interface} in native DRV_MODE")]
        XdpAttachedNative { interface: String } => tracing::Level::INFO,

        #[error("XDP DRV_MODE failed on {interface}: {error}. Falling back to SKB_MODE.")]
        XdpDrvModeFailed { interface: String, error: String } => tracing::Level::WARN,

        #[error("XDP attached to {interface} in generic SKB_MODE (reduced performance). For best performance, use a NIC with native XDP support (e.g., virtio-net, Intel i40e/ice).")]
        XdpAttachedSkb { interface: String } => tracing::Level::WARN,

        #[error("XDP attach failed on {interface} with both DRV_MODE and SKB_MODE. Ensure the interface exists and supports XDP. Supported NICs: virtio-net, Intel i40e/ice/i350, Mellanox mlx5. SKB error: {error}")]
        XdpAttachFailed { interface: String, error: String } => tracing::Level::ERROR,
    }
}
