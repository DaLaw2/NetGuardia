use super::helpers::{override_parsed, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct ObservabilityConfig {
    pub log_buffer_capacity: usize,
    pub log_buffer_max_message_bytes: usize,
    pub log_max_download_size: u64,
    pub log_live_default_limit: usize,
    pub log_live_max_limit: usize,
    pub fusion_explain_scan_limit: i64,
    pub fusion_explain_response_cap: usize,
    pub default_event_channel_capacity: usize,
    pub drop_channel_capacity: usize,
}

impl ObservabilityConfig {
    pub fn defaults() -> Self {
        Self {
            log_buffer_capacity: 5_000,
            log_buffer_max_message_bytes: 8_192,
            log_max_download_size: 50 * 1024 * 1024,
            log_live_default_limit: 500,
            log_live_max_limit: 2_000,
            fusion_explain_scan_limit: 5_000,
            fusion_explain_response_cap: 200,
            default_event_channel_capacity: 256,
            drop_channel_capacity: 100,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.log_buffer_capacity, repo, "log_buffer_capacity")?;
        override_parsed(
            &mut cfg.log_buffer_max_message_bytes,
            repo,
            "log_buffer_max_message_bytes",
        )?;
        override_parsed(&mut cfg.log_max_download_size, repo, "log_max_download_size")?;
        override_parsed(&mut cfg.log_live_default_limit, repo, "log_live_default_limit")?;
        override_parsed(&mut cfg.log_live_max_limit, repo, "log_live_max_limit")?;
        override_parsed(&mut cfg.fusion_explain_scan_limit, repo, "fusion_explain_scan_limit")?;
        override_parsed(
            &mut cfg.fusion_explain_response_cap,
            repo,
            "fusion_explain_response_cap",
        )?;
        override_parsed(
            &mut cfg.default_event_channel_capacity,
            repo,
            "default_event_channel_capacity",
        )?;
        override_parsed(&mut cfg.drop_channel_capacity, repo, "drop_channel_capacity")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "log_buffer_capacity", "5000")?;
        seed_key(repo, "log_buffer_max_message_bytes", "8192")?;
        seed_key(repo, "log_max_download_size", &(50_u64 * 1024 * 1024).to_string())?;
        seed_key(repo, "log_live_default_limit", "500")?;
        seed_key(repo, "log_live_max_limit", "2000")?;
        seed_key(repo, "fusion_explain_scan_limit", "5000")?;
        seed_key(repo, "fusion_explain_response_cap", "200")?;
        seed_key(repo, "default_event_channel_capacity", "256")?;
        seed_key(repo, "drop_channel_capacity", "100")?;
        Ok(())
    }
}
