use macros::loggable;
use tracing;

loggable! {
    EbpfLog {
        #[error("Attach XDP program success")]
        AttachProgramSuccess => tracing::Level::INFO,
    }
}
