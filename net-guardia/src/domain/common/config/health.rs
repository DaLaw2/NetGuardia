use macros::config_settings;

#[config_settings(section = "health")]
#[derive(Debug, Clone)]
pub struct HealthConfig {
    #[setting(key = "health_cpu_issue_percent", default = "90.0")]
    pub cpu_issue_percent: f32,
    #[setting(key = "health_cpu_warn_percent", default = "75.0")]
    pub cpu_warn_percent: f32,
    #[setting(key = "health_mem_issue_percent", default = "95.0")]
    pub mem_issue_percent: f32,
    #[setting(key = "health_mem_warn_percent", default = "80.0")]
    pub mem_warn_percent: f32,
    #[setting(key = "health_disk_issue_percent", default = "95.0")]
    pub disk_issue_percent: f32,
    #[setting(key = "health_disk_warn_percent", default = "90.0")]
    pub disk_warn_percent: f32,
    #[setting(key = "health_temp_issue_celsius", default = "80.0")]
    pub temp_issue_celsius: f32,
    #[setting(key = "health_temp_warn_celsius", default = "70.0")]
    pub temp_warn_celsius: f32,
    #[setting(key = "health_monitoring_interval_secs", default = "5")]
    pub monitoring_interval_secs: u64,
    #[setting(key = "health_broadcast_channel_capacity", default = "100")]
    pub broadcast_channel_capacity: usize,
}
