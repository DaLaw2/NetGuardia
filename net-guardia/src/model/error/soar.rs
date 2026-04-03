use macros::traceable;

traceable! {
    SoarError {
        #[no_source]
        #[error("Auto-block cap reached (max {max_cap} concurrent blocks)")]
        CapReached { max_cap: u32 } => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid TTL: {ttl_secs}s exceeds maximum of {max_secs}s")]
        InvalidTtl { ttl_secs: u64, max_secs: u64 } => tracing::Level::WARN,

        #[no_source]
        #[error("SOAR action failed: {action_type} — {reason}")]
        ActionFailed { action_type: String, reason: String } => tracing::Level::ERROR,

        #[error("Failed to clean up ACL rule after unblock: {err}")]
        AclCleanupFailed => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid playbook condition: {condition_type} — {reason}")]
        InvalidCondition { condition_type: String, reason: String } => tracing::Level::WARN,
    }
}
