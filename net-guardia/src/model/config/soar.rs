use super::helpers::{override_parsed, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct SoarConfig {
    pub max_auto_block_cap: u32,
    pub max_ttl_secs: u64,
    pub handle_concurrency: usize,
    pub max_pending_unblock_retries: i64,
    pub default_block_ttl_secs: u64,
    pub default_rate_limit_factor: f64,
    pub default_rate_limit_ttl_secs: u64,
    pub default_webhook_timeout_secs: u64,
    pub default_frequency_window_secs: u64,
    pub default_single_source_high_min_confidence: f32,
    pub default_cooldown_expiry_secs: u64,
    pub rate_limit_cmd_channel_capacity: usize,
    pub frequency_max_tracked_keys: usize,
    pub fallback_cooldown_secs: i64,
}

impl SoarConfig {
    pub fn defaults() -> Self {
        Self {
            max_auto_block_cap: 100,
            max_ttl_secs: 86_400,
            handle_concurrency: 16,
            max_pending_unblock_retries: 5,
            default_block_ttl_secs: 1800,
            default_rate_limit_factor: 0.5,
            default_rate_limit_ttl_secs: 600,
            default_webhook_timeout_secs: 10,
            default_frequency_window_secs: 60,
            default_single_source_high_min_confidence: 0.95,
            default_cooldown_expiry_secs: 3600,
            rate_limit_cmd_channel_capacity: 64,
            frequency_max_tracked_keys: 50_000,
            fallback_cooldown_secs: 300,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.max_auto_block_cap, repo, "soar_max_auto_block_cap")?;
        override_parsed(&mut cfg.max_ttl_secs, repo, "soar_max_ttl_secs")?;
        override_parsed(&mut cfg.handle_concurrency, repo, "soar_handle_concurrency")?;
        override_parsed(
            &mut cfg.max_pending_unblock_retries,
            repo,
            "soar_max_pending_unblock_retries",
        )?;
        override_parsed(&mut cfg.default_block_ttl_secs, repo, "soar_default_block_ttl_secs")?;
        override_parsed(
            &mut cfg.default_rate_limit_factor,
            repo,
            "soar_default_rate_limit_factor",
        )?;
        override_parsed(
            &mut cfg.default_rate_limit_ttl_secs,
            repo,
            "soar_default_rate_limit_ttl_secs",
        )?;
        override_parsed(
            &mut cfg.default_webhook_timeout_secs,
            repo,
            "soar_default_webhook_timeout_secs",
        )?;
        override_parsed(
            &mut cfg.default_frequency_window_secs,
            repo,
            "soar_default_frequency_window_secs",
        )?;
        override_parsed(
            &mut cfg.default_single_source_high_min_confidence,
            repo,
            "soar_default_single_source_high_min_confidence",
        )?;
        override_parsed(
            &mut cfg.default_cooldown_expiry_secs,
            repo,
            "soar_default_cooldown_expiry_secs",
        )?;
        override_parsed(
            &mut cfg.rate_limit_cmd_channel_capacity,
            repo,
            "soar_rate_limit_cmd_channel_capacity",
        )?;
        override_parsed(
            &mut cfg.frequency_max_tracked_keys,
            repo,
            "soar_frequency_max_tracked_keys",
        )?;
        override_parsed(&mut cfg.fallback_cooldown_secs, repo, "soar_fallback_cooldown_secs")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "soar_max_auto_block_cap", "100")?;
        seed_key(repo, "soar_max_ttl_secs", "86400")?;
        seed_key(repo, "soar_handle_concurrency", "16")?;
        seed_key(repo, "soar_max_pending_unblock_retries", "5")?;
        seed_key(repo, "soar_default_block_ttl_secs", "1800")?;
        seed_key(repo, "soar_default_rate_limit_factor", "0.5")?;
        seed_key(repo, "soar_default_rate_limit_ttl_secs", "600")?;
        seed_key(repo, "soar_default_webhook_timeout_secs", "10")?;
        seed_key(repo, "soar_default_frequency_window_secs", "60")?;
        seed_key(repo, "soar_default_single_source_high_min_confidence", "0.95")?;
        seed_key(repo, "soar_default_cooldown_expiry_secs", "3600")?;
        seed_key(repo, "soar_rate_limit_cmd_channel_capacity", "64")?;
        seed_key(repo, "soar_frequency_max_tracked_keys", "50000")?;
        seed_key(repo, "soar_fallback_cooldown_secs", "300")?;
        Ok(())
    }
}
