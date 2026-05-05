use macros::config_settings;

#[config_settings(section = "telegram")]
#[derive(Debug, Clone)]
pub struct TelegramConfig {
    #[setting(key = "telegram_rate_limit_max_messages", default = "20")]
    pub rate_limit_max_messages: u32,
    #[setting(key = "telegram_rate_limit_window_secs", default = "60")]
    pub rate_limit_window_secs: u32,
    #[setting(key = "telegram_max_retries", default = "2")]
    pub max_retries: u32,
}

#[config_settings(section = "smtp")]
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    #[setting(key = "smtp_host", default = "")]
    pub host: String,
    #[setting(key = "smtp_port", default = "587")]
    pub port: u16,
    #[setting(key = "smtp_username", default = "")]
    pub username: String,
    #[setting(key = "smtp_sender", default = "")]
    pub sender: String,
    #[setting(key = "smtp_recipient", default = "")]
    pub recipient: String,
}

#[config_settings]
#[derive(Debug, Clone)]
pub struct NotificationConfig {
    #[setting(flatten)]
    pub telegram: TelegramConfig,
    #[setting(flatten)]
    pub smtp: SmtpConfig,
}
