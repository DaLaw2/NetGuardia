use macros::config_settings;

#[config_settings(section = "system")]
#[derive(Debug, Clone)]
pub struct SystemConfig {
    #[setting(key = "enforce_mode", default = "monitor")]
    pub enforce_mode: String,
    #[setting(key = "database_path", default = "net-guardia.db", api = false)]
    pub database_path: String,
    #[setting(key = "report_dir", default = "/var/lib/netguardia/reports", api = false)]
    pub report_dir: String,
    #[setting(key = "log_dir", default = "logs", api = false)]
    pub log_dir: String,
}
