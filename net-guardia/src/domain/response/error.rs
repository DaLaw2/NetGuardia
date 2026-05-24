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
        #[error("Invalid TTL: {ttl_secs}s must be greater than 0")]
        InvalidTtlNonPositive { ttl_secs: u64 } => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid TTL: {ttl_secs}s is too large to schedule safely")]
        TtlTooLarge { ttl_secs: u64 } => tracing::Level::WARN,

        #[error("SOAR action failed: {action_type} — {err}")]
        ActionFailed { action_type: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown SOAR action type: {action_type}")]
        UnknownActionType { action_type: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Rate limit config not available for SOAR action")]
        RateLimitUnavailable => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid rate limit factor: {factor} (must be 0.01..=1.0)")]
        InvalidRateLimitFactor { factor: f64 } => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook action missing required parameter: {param}")]
        WebhookMissingParam { param: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook URL has no host")]
        WebhookUrlNoHost => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook URL scheme '{scheme}' is not supported")]
        WebhookUnsupportedScheme { scheme: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook DNS resolution returned no addresses for '{host}'")]
        WebhookDnsEmpty { host: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook SSRF blocked: host '{host}' resolves to non-public IP {ip}")]
        WebhookSsrfBlocked { host: String, ip: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Webhook returned non-success HTTP status: {status}")]
        WebhookHttpStatus { status: u16 } => tracing::Level::WARN,

        #[no_source]
        #[error("Manual unblock failed: block rule {id} not found")]
        UnblockRuleNotFound { id: i64 } => tracing::Level::WARN,

        #[error("Failed to clean up ACL rule after unblock: {err}")]
        AclCleanupFailed => tracing::Level::WARN,

        #[error("Failed to queue pending unblock for IP {source_ip}: {err}")]
        PendingUnblockQueueFailed { source_ip: String } => tracing::Level::ERROR,

        #[no_source]
        #[error("Unknown SOAR condition type: {condition_type}")]
        UnknownConditionType { condition_type: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Invalid operator '{operator}' for SOAR condition type '{condition_type}'")]
        InvalidConditionOperator { condition_type: String, operator: String } => tracing::Level::WARN,

        #[no_source]
        #[error("{reason}")]
        ValidationFailed { reason: String } => tracing::Level::WARN,

        #[no_source]
        #[error("Rate-limit owner task is unavailable (channel closed)")]
        RateLimitOwnerUnavailable => tracing::Level::ERROR,

        #[error("Rate-limit owner blocking task panicked or was cancelled: {err}")]
        RateLimitOwnerJoinFailed => tracing::Level::ERROR,
    }
}
