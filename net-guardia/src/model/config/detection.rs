use super::helpers::{override_parsed, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub fusion: FusionConfig,
    pub beaconing: BeaconingConfig,
    pub cleanup_interval_secs: u64,
}

impl DetectionConfig {
    pub fn defaults() -> Self {
        Self {
            fusion: FusionConfig::defaults(),
            beaconing: BeaconingConfig::defaults(),
            cleanup_interval_secs: 60,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        cfg.fusion = FusionConfig::from_settings(repo)?;
        cfg.beaconing = BeaconingConfig::from_settings(repo)?;
        override_parsed(&mut cfg.cleanup_interval_secs, repo, "detection_cleanup_interval_secs")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        FusionConfig::seed_defaults(repo)?;
        BeaconingConfig::seed_defaults(repo)?;
        seed_key(repo, "detection_cleanup_interval_secs", "60")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct FusionConfig {
    pub dedup_window_secs: u64,
    pub repeat_offender_window_secs: u64,
    pub max_dedup_entries: usize,
}

impl FusionConfig {
    pub fn defaults() -> Self {
        Self {
            dedup_window_secs: 30,
            repeat_offender_window_secs: 2 * 60 * 60,
            max_dedup_entries: 50_000,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.dedup_window_secs, repo, "fusion_dedup_window_secs")?;
        override_parsed(
            &mut cfg.repeat_offender_window_secs,
            repo,
            "fusion_repeat_offender_window_secs",
        )?;
        override_parsed(&mut cfg.max_dedup_entries, repo, "fusion_max_dedup_entries")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "fusion_dedup_window_secs", "30")?;
        seed_key(repo, "fusion_repeat_offender_window_secs", "7200")?;
        seed_key(repo, "fusion_max_dedup_entries", "50000")?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BeaconingConfig {
    pub analysis_interval_secs: u64,
    pub min_observations: usize,
    pub cv_threshold: f64,
    pub max_cache_entries: usize,
    pub expiry_secs: u64,
    pub alert_cooldown_secs: u64,
}

impl BeaconingConfig {
    pub fn defaults() -> Self {
        Self {
            analysis_interval_secs: 30,
            min_observations: 5,
            cv_threshold: 0.3,
            max_cache_entries: 50_000,
            expiry_secs: 600,
            alert_cooldown_secs: 300,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(
            &mut cfg.analysis_interval_secs,
            repo,
            "beaconing_analysis_interval_secs",
        )?;
        override_parsed(&mut cfg.min_observations, repo, "beaconing_min_observations")?;
        override_parsed(&mut cfg.cv_threshold, repo, "beaconing_cv_threshold")?;
        override_parsed(&mut cfg.max_cache_entries, repo, "beaconing_max_cache_entries")?;
        override_parsed(&mut cfg.expiry_secs, repo, "beaconing_expiry_secs")?;
        override_parsed(&mut cfg.alert_cooldown_secs, repo, "beaconing_alert_cooldown_secs")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "beaconing_analysis_interval_secs", "30")?;
        seed_key(repo, "beaconing_min_observations", "5")?;
        seed_key(repo, "beaconing_cv_threshold", "0.3")?;
        seed_key(repo, "beaconing_max_cache_entries", "50000")?;
        seed_key(repo, "beaconing_expiry_secs", "600")?;
        seed_key(repo, "beaconing_alert_cooldown_secs", "300")?;
        Ok(())
    }
}
