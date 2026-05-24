use macros::config_settings;

use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::domain::common::config::require_config_field;

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

impl ObservabilityConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.log_buffer_capacity > 0, "observability.log_buffer_capacity")?;
        require_config_field(
            self.log_buffer_max_message_bytes > 0,
            "observability.log_buffer_max_message_bytes",
        )?;
        require_config_field(self.log_live_default_limit > 0, "observability.log_live_default_limit")?;
        require_config_field(
            self.log_live_max_limit >= self.log_live_default_limit,
            "observability.log_live_max_limit",
        )?;
        require_config_field(
            self.fusion_explain_scan_limit > 0,
            "observability.fusion_explain_scan_limit",
        )?;
        require_config_field(
            self.fusion_explain_response_cap > 0,
            "observability.fusion_explain_response_cap",
        )?;
        let response_cap = i64::try_from(self.fusion_explain_response_cap)
            .map_err(|_| SystemError::InvalidConfigField("observability.fusion_explain_response_cap"))?;
        require_config_field(
            self.fusion_explain_scan_limit > response_cap,
            "observability.fusion_explain_scan_limit",
        )?;
        require_config_field(
            self.default_event_channel_capacity > 0,
            "observability.default_event_channel_capacity",
        )?;
        require_config_field(self.drop_channel_capacity > 0, "observability.drop_channel_capacity")
    }
}

#[cfg(test)]
mod tests {
    use super::ObservabilityConfig;

    #[test]
    fn fusion_explain_scan_limit_must_allow_truncation_detection() {
        let mut cfg = ObservabilityConfig::defaults();
        cfg.fusion_explain_scan_limit = 200;
        cfg.fusion_explain_response_cap = 200;

        assert!(cfg.validate().is_err());
    }
}
