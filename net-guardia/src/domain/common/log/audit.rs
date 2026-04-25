use macros::loggable;
use tracing;

loggable! {
    AuditLog {
        #[error("Audit event: actor={actor}, action={action}")]
        AuditEvent { actor: String, action: String } => tracing::Level::DEBUG,

        #[error("Audit drift event: {count} features drifted")]
        AuditDriftEvent { count: usize } => tracing::Level::DEBUG,

        #[error("AuditLogger: DB write failed ({error}), event logged only: actor={actor}, action={action}")]
        AuditDbWriteFailed { error: String, actor: String, action: String } => tracing::Level::WARN,

        #[error("AuditLogger: DB write failed for drift event: {error}")]
        AuditDriftDbWriteFailed { error: String } => tracing::Level::WARN,

        #[error("AuditLogger lagged by {count} events")]
        AuditLagged { count: u64 } => tracing::Level::WARN,

        #[error("AuditLogger: event channel closed")]
        AuditChannelClosed => tracing::Level::INFO,
    }
}
