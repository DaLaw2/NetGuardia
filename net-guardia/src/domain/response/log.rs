use macros::loggable;
use tracing;

loggable! {
    SoarLog {
        #[error("SOAR engine started, listening for threat events")]
        EngineStarted => tracing::Level::INFO,

        #[error("SOAR TTL scheduler started")]
        TtlSchedulerStarted => tracing::Level::INFO,

        #[error("SOAR event channel closed, shutting down")]
        ChannelClosed => tracing::Level::INFO,

        #[error("SOAR event receiver lagged by {count} events")]
        ReceiverLagged { count: u64 } => tracing::Level::WARN,

        #[error("SOAR cache loaded: {playbooks} playbooks, {whitelisted} whitelisted IPs, {active_blocks} active blocks")]
        CacheLoaded { playbooks: usize, whitelisted: usize, active_blocks: u32 } => tracing::Level::INFO,

        #[error("Playbook '{name}' executed for IP {source_ip} (threat: {attack_type})")]
        PlaybookExecuted { name: String, source_ip: String, attack_type: String } => tracing::Level::INFO,

        #[error("Playbook '{name}' execution error: {error}")]
        PlaybookError { name: String, error: String } => tracing::Level::WARN,

        #[error("No matching playbook for event type '{attack_type}', executing fallback")]
        FallbackTriggered { attack_type: String } => tracing::Level::DEBUG,

        #[error("Cooldown active for playbook '{name}' and IP {source_ip}")]
        CooldownActive { name: String, source_ip: String } => tracing::Level::DEBUG,

        #[error("IP {ip} is in admin whitelist, skipping playbook '{name}'")]
        WhitelistSkipped { ip: String, name: String } => tracing::Level::DEBUG,

        #[error("Blocked IP {ip} for {ttl_secs}s")]
        IpBlocked { ip: String, ttl_secs: u64 } => tracing::Level::INFO,

        #[error("Auto-block cap reached ({current}/{max}), skipping block for IP {ip}")]
        CapReached { current: u32, max: u32, ip: String } => tracing::Level::WARN,

        #[error("Telegram notification sent")]
        TelegramSent => tracing::Level::INFO,

        #[error("Telegram not configured, skipping send_telegram action")]
        TelegramNotConfigured => tracing::Level::DEBUG,

        #[error("SOAR fallback executed for IP {ip} (no matching playbook)")]
        FallbackExecuted { ip: String } => tracing::Level::INFO,

        #[error("SOAR recovery: re-applied {count} active block rules to eBPF")]
        RecoveryComplete { count: usize } => tracing::Level::INFO,

        #[error("Failed to recover block for IP {ip} during startup: {error}")]
        RecoveryFailed { ip: String, error: String } => tracing::Level::WARN,

        #[error("Block enforcement gap: IP {ip} is persisted in DB but eBPF enforcement failed — block is not active until next successful recovery")]
        BlockEnforcementGap { ip: String } => tracing::Level::ERROR,

        #[error("Successfully unblocked orphan IP {ip} on retry #{attempt}")]
        PendingUnblockRecovered { ip: String, attempt: i64 } => tracing::Level::INFO,

        #[error("SOAR adjust_rate_limit: factor={factor}, ttl={ttl_secs}s, trigger=IP {ip} ({attack_type}). {details}")]
        RateLimitAdjusted { factor: String, ttl_secs: u64, ip: String, attack_type: String, details: String } => tracing::Level::INFO,

        #[error("SOAR rate limit adjustment expired — original rates restored")]
        RateLimitRestored => tracing::Level::INFO,

        #[error("SOAR rate limit restoration partially failed: {errors}")]
        RateLimitRestoreFailed { errors: String } => tracing::Level::ERROR,

        #[error("[monitor] Action '{action_type}' skipped for IP {source_ip} — enforce mode is not active")]
        MonitorModeSkipped { action_type: String, source_ip: String } => tracing::Level::DEBUG,

        #[error("SOAR threat event handling failed: {error}")]
        ThreatEventHandlingFailed { error: String } => tracing::Level::ERROR,

        #[error("TTL sweep failed: {error}")]
        TtlSweepFailed { error: String } => tracing::Level::ERROR,

        #[error("Rate limit restoration check failed: {error}")]
        RateLimitRestorationCheckFailed { error: String } => tracing::Level::ERROR,

        #[error("Failed to load pending unblocks: {error}")]
        PendingUnblocksLoadFailed { error: String } => tracing::Level::ERROR,

        #[error("Giving up on pending unblock for IP {ip} after {retries} retries")]
        PendingUnblockRetryExhausted { ip: String, retries: i64 } => tracing::Level::ERROR,

        #[error("Retry #{attempt} failed to unblock orphan IP {ip}: {error}")]
        PendingUnblockRetryFailed { ip: String, attempt: i64, error: String } => tracing::Level::WARN,

        #[error("Failed to delete pending unblock {id} for IP {ip} after {reason}: {error}")]
        PendingUnblockDeleteFailed { id: i64, ip: String, reason: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to increment pending unblock retry {id} for IP {ip}: {error}")]
        PendingUnblockRetryIncrementFailed { id: i64, ip: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to mark pending unblock {id} for IP {ip} as exhausted: {error}")]
        PendingUnblockExhaustMarkFailed { id: i64, ip: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to unblock IP {ip} after DB error; queueing for retry: {error}")]
        BlockRollbackUnblockFailed { ip: String, error: String } => tracing::Level::ERROR,

        #[error("Failed to queue pending unblock for IP {ip}: {error}")]
        PendingUnblockQueueFailed { ip: String, error: String } => tracing::Level::ERROR,

        #[error("SSRF blocked: webhook host '{host}' resolved to non-public IP {ip}")]
        WebhookSsrfBlocked { host: String, ip: String } => tracing::Level::WARN,

        #[error("TTL sweep: {removed} blocks removed, {skipped} kept (manual ACL conflict)")]
        TtlSweepComplete { removed: u32, skipped: u32 } => tracing::Level::DEBUG,

        #[error("SOAR log action [{level}]: threat from {source_ip} — {attack_type} (confidence: {confidence}, diagnostics: {diagnostics})")]
        ActionLog { level: String, source_ip: String, attack_type: String, confidence: String, diagnostics: String } => tracing::Level::INFO,

        #[error("SOAR cooldown cleanup: {removed} expired entries removed")]
        CooldownCleanup { removed: u32 } => tracing::Level::DEBUG,

        #[error("Webhook sent to {url} (HTTP {status})")]
        WebhookSent { url: String, status: u16 } => tracing::Level::INFO,

        #[error("Webhook to {url} failed: {error}")]
        WebhookFailed { url: String, error: String } => tracing::Level::WARN,

        #[error("Condition '{condition_type}' not met for playbook '{name}' (value: {value})")]
        ConditionNotMet { condition_type: String, name: String, value: String } => tracing::Level::DEBUG,

        #[error("Frequency condition not met: {count}/{required} in {window_secs}s for playbook '{name}'")]
        FrequencyNotMet { name: String, count: u64, required: u64, window_secs: u64 } => tracing::Level::DEBUG,

        #[error("Frequency cleanup: {removed} expired entries")]
        FrequencyCleanup { removed: u32 } => tracing::Level::DEBUG,

        #[error("Invalid operator '{operator}' for condition type '{condition_type}' on playbook '{name}', condition skipped")]
        InvalidConditionOperator { name: String, condition_type: String, operator: String } => tracing::Level::WARN,

        #[error("Playbook '{name}' uses non-canonical trigger_event '{trigger_event}' — cross-source fusion dedup may silently miss this rule")]
        NonCanonicalTriggerEvent { name: String, trigger_event: String } => tracing::Level::WARN,
    }
}
