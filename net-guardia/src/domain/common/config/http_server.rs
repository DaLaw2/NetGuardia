use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "http")]
#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    #[setting(key = "http_port", default = "8080")]
    pub port: u16,
    #[setting(key = "cors_allowed_origins", default = "", api = false)]
    pub cors_allowed_origins: Vec<String>,
    #[setting(key = "force_https", default = "false")]
    pub force_https: bool,
    #[setting(key = "session_expiry_hours", default = "24")]
    pub session_expiry_hours: u64,
    #[setting(key = "session_idle_timeout_minutes", default = "30")]
    pub session_idle_timeout_minutes: u64,
}

impl HttpServerConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.port > 0, "http_server.port")?;
        require_config_field(self.session_expiry_hours > 0, "http_server.session_expiry_hours")?;
        require_config_field(
            self.session_idle_timeout_minutes > 0,
            "http_server.session_idle_timeout_minutes",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HttpServerConfig;

    #[test]
    fn zero_session_limits_are_invalid() {
        let mut cfg = HttpServerConfig::defaults();
        cfg.session_expiry_hours = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = HttpServerConfig::defaults();
        cfg.session_idle_timeout_minutes = 0;
        assert!(cfg.validate().is_err());
    }
}
