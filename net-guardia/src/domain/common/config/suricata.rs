use super::helpers::{override_bool, override_parsed, override_string_nonempty, seed_key};
use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

#[derive(Debug, Clone)]
pub struct SuricataConfig {
    pub enabled: bool,
    pub binary_path: String,
    pub config_path: String,
    pub eve_log_path: String,
    pub auto_restart_on_crash: bool,
    pub restart_backoff_secs: u64,
    pub poll_interval_ms: u64,
    pub file_wait_interval_secs: u64,
    pub confidence_high: f32,
    pub confidence_medium: f32,
    pub confidence_low: f32,
    pub confidence_info: f32,
}

impl SuricataConfig {
    pub fn defaults() -> Self {
        Self {
            enabled: false,
            binary_path: "/usr/bin/suricata".to_string(),
            config_path: "/etc/netguardia/suricata.yaml".to_string(),
            eve_log_path: "/var/log/netguardia/eve.json".to_string(),
            auto_restart_on_crash: true,
            restart_backoff_secs: 10,
            poll_interval_ms: 200,
            file_wait_interval_secs: 1,
            confidence_high: 0.95,
            confidence_medium: 0.80,
            confidence_low: 0.65,
            confidence_info: 0.50,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_bool(&mut cfg.enabled, repo, "suricata_enabled")?;
        override_string_nonempty(&mut cfg.binary_path, repo, "suricata_binary_path")?;
        override_string_nonempty(&mut cfg.config_path, repo, "suricata_config_path")?;
        override_string_nonempty(&mut cfg.eve_log_path, repo, "suricata_eve_log_path")?;
        override_bool(&mut cfg.auto_restart_on_crash, repo, "suricata_auto_restart_on_crash")?;
        override_parsed(&mut cfg.restart_backoff_secs, repo, "suricata_restart_backoff_secs")?;
        override_parsed(&mut cfg.poll_interval_ms, repo, "suricata_poll_interval_ms")?;
        override_parsed(
            &mut cfg.file_wait_interval_secs,
            repo,
            "suricata_file_wait_interval_secs",
        )?;
        override_parsed(&mut cfg.confidence_high, repo, "suricata_confidence_high")?;
        override_parsed(&mut cfg.confidence_medium, repo, "suricata_confidence_medium")?;
        override_parsed(&mut cfg.confidence_low, repo, "suricata_confidence_low")?;
        override_parsed(&mut cfg.confidence_info, repo, "suricata_confidence_info")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "suricata_enabled", "false")?;
        seed_key(repo, "suricata_binary_path", "/usr/bin/suricata")?;
        seed_key(repo, "suricata_config_path", "/etc/netguardia/suricata.yaml")?;
        seed_key(repo, "suricata_eve_log_path", "/var/log/netguardia/eve.json")?;
        seed_key(repo, "suricata_auto_restart_on_crash", "true")?;
        seed_key(repo, "suricata_restart_backoff_secs", "10")?;
        seed_key(repo, "suricata_poll_interval_ms", "200")?;
        seed_key(repo, "suricata_file_wait_interval_secs", "1")?;
        seed_key(repo, "suricata_confidence_high", "0.95")?;
        seed_key(repo, "suricata_confidence_medium", "0.80")?;
        seed_key(repo, "suricata_confidence_low", "0.65")?;
        seed_key(repo, "suricata_confidence_info", "0.50")?;
        Ok(())
    }
}
