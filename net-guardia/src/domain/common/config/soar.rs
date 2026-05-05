use macros::config_settings;

#[config_settings(section = "soar")]
#[derive(Debug, Clone)]
pub struct SoarConfig {
    #[setting(key = "soar_max_auto_block_cap", default = "100")]
    pub max_auto_block_cap: u32,
    #[setting(key = "soar_max_ttl_secs", default = "86400")]
    pub max_ttl_secs: u64,
    #[setting(key = "soar_handle_concurrency", default = "16")]
    pub handle_concurrency: usize,
    #[setting(key = "soar_max_pending_unblock_retries", default = "5")]
    pub max_pending_unblock_retries: i64,
    #[setting(key = "soar_default_block_ttl_secs", default = "1800")]
    pub default_block_ttl_secs: u64,
    #[setting(key = "soar_default_rate_limit_factor", default = "0.5")]
    pub default_rate_limit_factor: f64,
    #[setting(key = "soar_default_rate_limit_ttl_secs", default = "600")]
    pub default_rate_limit_ttl_secs: u64,
    #[setting(key = "soar_default_webhook_timeout_secs", default = "10")]
    pub default_webhook_timeout_secs: u64,
    #[setting(key = "soar_default_frequency_window_secs", default = "60")]
    pub default_frequency_window_secs: u64,
    #[setting(key = "soar_default_single_source_high_min_confidence", default = "0.95")]
    pub default_single_source_high_min_confidence: f32,
    #[setting(key = "soar_default_cooldown_expiry_secs", default = "3600")]
    pub default_cooldown_expiry_secs: u64,
    #[setting(key = "soar_rate_limit_cmd_channel_capacity", default = "64")]
    pub rate_limit_cmd_channel_capacity: usize,
    #[setting(key = "soar_frequency_max_tracked_keys", default = "50000")]
    pub frequency_max_tracked_keys: usize,
    #[setting(key = "soar_frequency_max_events_per_key", default = "200")]
    pub frequency_max_events_per_key: usize,
    #[setting(key = "soar_frequency_retention_secs", default = "7200")]
    pub frequency_retention_secs: u64,
    #[setting(key = "soar_fallback_cooldown_secs", default = "300")]
    pub fallback_cooldown_secs: i64,
    #[setting(key = "soar_execution_list_limit", default = "100")]
    pub execution_list_limit: i64,
}
