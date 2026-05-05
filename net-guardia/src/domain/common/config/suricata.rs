use macros::config_settings;

#[config_settings(section = "suricata")]
#[derive(Debug, Clone)]
pub struct SuricataConfig {
    #[setting(key = "suricata_enabled", default = "false")]
    pub enabled: bool,
    #[setting(key = "suricata_binary_path", default = "/usr/bin/suricata")]
    pub binary_path: String,
    #[setting(key = "suricata_config_path", default = "/etc/netguardia/suricata.yaml")]
    pub config_path: String,
    #[setting(key = "suricata_eve_log_path", default = "/var/log/netguardia/eve.json")]
    pub eve_log_path: String,
    #[setting(key = "suricata_auto_restart_on_crash", default = "true")]
    pub auto_restart_on_crash: bool,
    #[setting(key = "suricata_restart_backoff_secs", default = "10")]
    pub restart_backoff_secs: u64,
    #[setting(key = "suricata_poll_interval_ms", default = "200")]
    pub poll_interval_ms: u64,
    #[setting(key = "suricata_file_wait_interval_secs", default = "1")]
    pub file_wait_interval_secs: u64,
    #[setting(key = "suricata_confidence_high", default = "0.95")]
    pub confidence_high: f32,
    #[setting(key = "suricata_confidence_medium", default = "0.80")]
    pub confidence_medium: f32,
    #[setting(key = "suricata_confidence_low", default = "0.65")]
    pub confidence_low: f32,
    #[setting(key = "suricata_confidence_info", default = "0.50")]
    pub confidence_info: f32,
}
