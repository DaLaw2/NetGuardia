use macros::config_settings;

#[config_settings(section = "http")]
#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    #[setting(key = "http_port", default = "8080")]
    pub port: u16,
    #[setting(key = "cors_allowed_origins", default = "", api = false)]
    pub cors_allowed_origins: Vec<String>,
    #[setting(key = "force_https", default = "false")]
    pub force_https: bool,
    #[setting(key = "jwt_expiry_hours", default = "24")]
    pub jwt_expiry_hours: u64,
}
