use macros::config_settings;

#[config_settings(section = "observability")]
#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    #[setting(key = "log_level", default = "info", default_debug = "debug")]
    pub log_level: String,
    #[setting(key = "log_buffer_capacity", default = "5000")]
    pub log_buffer_capacity: usize,
    #[setting(key = "log_buffer_max_message_bytes", default = "8192")]
    pub log_buffer_max_message_bytes: usize,
    #[setting(key = "log_max_download_size", default = "52428800")]
    pub log_max_download_size: u64,
    #[setting(key = "log_live_default_limit", default = "500")]
    pub log_live_default_limit: usize,
    #[setting(key = "log_live_max_limit", default = "2000")]
    pub log_live_max_limit: usize,
    #[setting(key = "fusion_explain_scan_limit", default = "5000")]
    pub fusion_explain_scan_limit: i64,
    #[setting(key = "fusion_explain_response_cap", default = "200")]
    pub fusion_explain_response_cap: usize,
    #[setting(key = "default_event_channel_capacity", default = "256")]
    pub default_event_channel_capacity: usize,
    #[setting(key = "drop_channel_capacity", default = "100")]
    pub drop_channel_capacity: usize,
}
