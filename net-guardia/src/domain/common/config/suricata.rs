use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

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

impl SuricataConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.restart_backoff_secs > 0, "suricata.restart_backoff_secs")?;
        require_config_field(self.poll_interval_ms > 0, "suricata.poll_interval_ms")?;
        require_config_field(self.file_wait_interval_secs > 0, "suricata.file_wait_interval_secs")?;
        require_config_field((0.0..=1.0).contains(&self.confidence_high), "suricata.confidence_high")?;
        require_config_field(
            (0.0..=1.0).contains(&self.confidence_medium),
            "suricata.confidence_medium",
        )?;
        require_config_field((0.0..=1.0).contains(&self.confidence_low), "suricata.confidence_low")?;
        require_config_field((0.0..=1.0).contains(&self.confidence_info), "suricata.confidence_info")?;
        require_config_field(
            self.confidence_high >= self.confidence_medium,
            "suricata.confidence_high",
        )?;
        require_config_field(
            self.confidence_medium >= self.confidence_low,
            "suricata.confidence_medium",
        )?;
        require_config_field(self.confidence_low >= self.confidence_info, "suricata.confidence_low")
    }
}

#[cfg(test)]
mod tests {
    use super::SuricataConfig;

    #[test]
    fn confidence_thresholds_must_follow_severity_order() {
        let mut cfg = SuricataConfig::defaults();
        cfg.confidence_high = 0.4;
        cfg.confidence_medium = 0.5;
        assert!(cfg.validate().is_err());

        let mut cfg = SuricataConfig::defaults();
        cfg.confidence_medium = 0.4;
        cfg.confidence_low = 0.5;
        assert!(cfg.validate().is_err());

        let mut cfg = SuricataConfig::defaults();
        cfg.confidence_low = 0.4;
        cfg.confidence_info = 0.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_timing_values_are_rejected() {
        let mut cfg = SuricataConfig::defaults();
        cfg.restart_backoff_secs = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = SuricataConfig::defaults();
        cfg.poll_interval_ms = 0;
        assert!(cfg.validate().is_err());

        let mut cfg = SuricataConfig::defaults();
        cfg.file_wait_interval_secs = 0;
        assert!(cfg.validate().is_err());
    }
}
