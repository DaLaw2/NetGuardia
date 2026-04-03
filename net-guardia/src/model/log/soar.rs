use macros::loggable;
use tracing;

loggable! {
    SoarLog {
        #[error("SOAR engine started, listening for threat events")]
        EngineStarted => tracing::Level::INFO,

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

        #[error("SOAR adjust_rate_limit: factor={factor}, ttl={ttl_secs}s, trigger=IP {ip} ({attack_type}). {details}")]
        RateLimitAdjusted { factor: String, ttl_secs: u64, ip: String, attack_type: String, details: String } => tracing::Level::INFO,

        #[error("SOAR rate limit adjustment expired — original rates restored")]
        RateLimitRestored => tracing::Level::INFO,

        #[error("SOAR rate limit restoration partially failed: {errors}")]
        RateLimitRestoreFailed { errors: String } => tracing::Level::ERROR,

        #[error("[monitor] Action '{action_type}' skipped for IP {source_ip} — enforce mode is not active")]
        MonitorModeSkipped { action_type: String, source_ip: String } => tracing::Level::DEBUG,

        #[error("SOAR event handling failed: {error}")]
        EventHandlingFailed { error: String } => tracing::Level::ERROR,

        #[error("TTL sweep: {removed} blocks removed, {skipped} kept (manual ACL conflict)")]
        TtlSweepComplete { removed: u32, skipped: u32 } => tracing::Level::DEBUG,

        #[error("SOAR log action [{level}]: threat from {source_ip} — {attack_type} (confidence: {confidence})")]
        ActionLog { level: String, source_ip: String, attack_type: String, confidence: String } => tracing::Level::INFO,

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
    }
}
