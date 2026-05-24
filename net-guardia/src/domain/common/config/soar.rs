use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

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

impl SoarConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.handle_concurrency > 0, "soar.handle_concurrency")?;
        require_config_field(
            self.rate_limit_cmd_channel_capacity > 0,
            "soar.rate_limit_cmd_channel_capacity",
        )?;
        require_config_field(self.max_auto_block_cap > 0, "soar.max_auto_block_cap")?;
        require_config_field(self.max_ttl_secs > 0, "soar.max_ttl_secs")?;
        require_config_field(
            self.max_pending_unblock_retries >= 0,
            "soar.max_pending_unblock_retries",
        )?;
        require_config_field(self.default_block_ttl_secs > 0, "soar.default_block_ttl_secs")?;
        require_config_field(
            self.default_block_ttl_secs <= self.max_ttl_secs,
            "soar.default_block_ttl_secs",
        )?;
        require_config_field(
            (0.01..=1.0).contains(&self.default_rate_limit_factor),
            "soar.default_rate_limit_factor",
        )?;
        require_config_field(self.default_rate_limit_ttl_secs > 0, "soar.default_rate_limit_ttl_secs")?;
        require_config_field(
            self.default_rate_limit_ttl_secs <= self.max_ttl_secs,
            "soar.default_rate_limit_ttl_secs",
        )?;
        require_config_field(
            self.default_webhook_timeout_secs > 0,
            "soar.default_webhook_timeout_secs",
        )?;
        require_config_field(
            self.default_frequency_window_secs > 0,
            "soar.default_frequency_window_secs",
        )?;
        require_config_field(
            self.default_cooldown_expiry_secs > 0,
            "soar.default_cooldown_expiry_secs",
        )?;
        require_config_field(self.frequency_max_tracked_keys > 0, "soar.frequency_max_tracked_keys")?;
        require_config_field(self.execution_list_limit > 0, "soar.execution_list_limit")?;
        require_config_field(
            self.frequency_max_events_per_key > 0,
            "soar.frequency_max_events_per_key",
        )?;
        require_config_field(self.frequency_retention_secs > 0, "soar.frequency_retention_secs")?;
        require_config_field(self.fallback_cooldown_secs >= 0, "soar.fallback_cooldown_secs")?;
        require_config_field(
            (0.0..=1.0).contains(&self.default_single_source_high_min_confidence),
            "soar.default_single_source_high_min_confidence",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::SoarConfig;

    #[test]
    fn negative_fallback_cooldown_is_invalid() {
        let mut cfg = SoarConfig::defaults();
        cfg.fallback_cooldown_secs = -1;

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn invalid_runtime_defaults_are_rejected() {
        let invalid_cases: [fn(&mut SoarConfig); 9] = [
            |cfg: &mut SoarConfig| cfg.max_auto_block_cap = 0,
            |cfg: &mut SoarConfig| cfg.max_ttl_secs = 0,
            |cfg: &mut SoarConfig| cfg.max_pending_unblock_retries = -1,
            |cfg: &mut SoarConfig| cfg.default_block_ttl_secs = 0,
            |cfg: &mut SoarConfig| cfg.default_rate_limit_factor = 0.0,
            |cfg: &mut SoarConfig| cfg.default_rate_limit_ttl_secs = 0,
            |cfg: &mut SoarConfig| cfg.default_webhook_timeout_secs = 0,
            |cfg: &mut SoarConfig| cfg.default_frequency_window_secs = 0,
            |cfg: &mut SoarConfig| cfg.default_cooldown_expiry_secs = 0,
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = SoarConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn default_ttls_must_not_exceed_max_ttl() {
        let mut cfg = SoarConfig::defaults();
        cfg.max_ttl_secs = 60;
        cfg.default_block_ttl_secs = 61;
        assert!(cfg.validate().is_err());

        let mut cfg = SoarConfig::defaults();
        cfg.max_ttl_secs = 60;
        cfg.default_rate_limit_ttl_secs = 61;
        assert!(cfg.validate().is_err());
    }
}
