use macros::traceable;

traceable! {
    SoarError {
        #[no_source]
        #[error("Playbook not found: id={playbook_id}")]
        PlaybookNotFound { playbook_id: i64 } => tracing::Level::WARN,

        #[no_source]
        #[error("Auto-block cap reached (max {max_cap} concurrent blocks)")]
        CapReached { max_cap: u32 } => tracing::Level::WARN,

        #[no_source]
        #[error("Cooldown active for playbook {playbook_id} and IP {source_ip}")]
        CooldownActive { playbook_id: i64, source_ip: String } => tracing::Level::DEBUG,

        #[no_source]
        #[error("IP {ip} is in admin whitelist, skipping auto-block")]
        AdminWhitelisted { ip: String } => tracing::Level::INFO,

        #[no_source]
        #[error("Invalid TTL: {ttl_secs}s exceeds maximum of {max_secs}s")]
        InvalidTtl { ttl_secs: u64, max_secs: u64 } => tracing::Level::WARN,

        #[no_source]
        #[error("SOAR action failed: {action_type} — {reason}")]
        ActionFailed { action_type: String, reason: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Duplicate block rule for IP {ip}")]
        DuplicateBlockRule { ip: String } => tracing::Level::DEBUG,

        #[error("Failed to clean up ACL rule after unblock: {err}")]
        AclCleanupFailed => tracing::Level::WARN,
    }
}
