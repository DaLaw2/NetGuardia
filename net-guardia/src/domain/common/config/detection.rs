use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "fusion")]
#[derive(Debug, Clone)]
pub struct FusionConfig {
    #[setting(key = "fusion_dedup_window_secs", default = "30")]
    pub dedup_window_secs: u64,
    #[setting(key = "fusion_repeat_offender_window_secs", default = "7200")]
    pub repeat_offender_window_secs: u64,
    #[setting(key = "fusion_max_dedup_entries", default = "50000")]
    pub max_dedup_entries: usize,
    #[setting(key = "fusion_source_count_max_entries", default = "10000")]
    pub source_count_max_entries: usize,
    #[setting(key = "fusion_repeat_tracker_max_entries", default = "5000")]
    pub repeat_tracker_max_entries: usize,
}

#[config_settings(section = "beaconing")]
#[derive(Debug, Clone)]
pub struct BeaconingConfig {
    #[setting(key = "beaconing_analysis_interval_secs", default = "30")]
    pub analysis_interval_secs: u64,
    #[setting(key = "beaconing_min_observations", default = "5")]
    pub min_observations: usize,
    #[setting(key = "beaconing_cv_threshold", default = "0.3")]
    pub cv_threshold: f64,
    #[setting(key = "beaconing_max_cache_entries", default = "50000")]
    pub max_cache_entries: usize,
    #[setting(key = "beaconing_max_timestamps_per_flow", default = "100")]
    pub max_timestamps_per_flow: usize,
    #[setting(key = "beaconing_expiry_secs", default = "600")]
    pub expiry_secs: u64,
    #[setting(key = "beaconing_alert_cooldown_secs", default = "300")]
    pub alert_cooldown_secs: u64,
}

#[config_settings(section = "flow_stats")]
#[derive(Debug, Clone)]
pub struct FlowStatsConfig {
    #[setting(key = "flow_stats_max_snapshot_entries", default = "10000")]
    pub max_snapshot_entries: usize,
    #[setting(key = "flow_stats_max_top_n", default = "10000")]
    pub max_top_n: usize,
}

#[config_settings(section = "detection")]
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    #[setting(flatten)]
    pub fusion: FusionConfig,
    #[setting(flatten)]
    pub beaconing: BeaconingConfig,
    #[setting(flatten)]
    pub flow_stats: FlowStatsConfig,
    #[setting(key = "detection_cleanup_interval_secs", default = "60")]
    pub cleanup_interval_secs: u64,
}

impl DetectionConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.cleanup_interval_secs > 0, "detection.cleanup_interval_secs")?;
        self.fusion.validate()?;
        self.beaconing.validate()?;
        self.flow_stats.validate()
    }
}

impl FusionConfig {
    fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_dedup_entries > 0, "detection.fusion.max_dedup_entries")?;
        require_config_field(
            self.source_count_max_entries > 0,
            "detection.fusion.source_count_max_entries",
        )?;
        require_config_field(
            self.repeat_tracker_max_entries > 0,
            "detection.fusion.repeat_tracker_max_entries",
        )?;
        require_config_field(self.dedup_window_secs > 0, "detection.fusion.dedup_window_secs")
    }
}

impl BeaconingConfig {
    fn validate(&self) -> Result<(), Error> {
        require_config_field(self.min_observations > 0, "detection.beaconing.min_observations")?;
        require_config_field(
            self.analysis_interval_secs > 0,
            "detection.beaconing.analysis_interval_secs",
        )?;
        require_config_field(
            self.cv_threshold.is_finite() && self.cv_threshold > 0.0,
            "detection.beaconing.cv_threshold",
        )?;
        require_config_field(self.max_cache_entries > 0, "detection.beaconing.max_cache_entries")?;
        require_config_field(
            self.max_timestamps_per_flow > 1,
            "detection.beaconing.max_timestamps_per_flow",
        )?;
        require_config_field(
            self.min_observations <= self.max_timestamps_per_flow,
            "detection.beaconing.min_observations",
        )?;
        require_config_field(self.expiry_secs > 0, "detection.beaconing.expiry_secs")
    }
}

impl FlowStatsConfig {
    fn validate(&self) -> Result<(), Error> {
        require_config_field(
            self.max_snapshot_entries > 0,
            "detection.flow_stats.max_snapshot_entries",
        )?;
        require_config_field(
            self.max_top_n >= self.max_snapshot_entries,
            "detection.flow_stats.max_top_n",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::DetectionConfig;

    #[test]
    fn invalid_beaconing_runtime_settings_are_rejected() {
        let invalid_cases: [fn(&mut DetectionConfig); 4] = [
            |cfg: &mut DetectionConfig| cfg.beaconing.analysis_interval_secs = 0,
            |cfg: &mut DetectionConfig| cfg.beaconing.cv_threshold = 0.0,
            |cfg: &mut DetectionConfig| cfg.beaconing.cv_threshold = f64::NAN,
            |cfg: &mut DetectionConfig| cfg.beaconing.expiry_secs = 0,
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = DetectionConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn beaconing_min_observations_must_fit_timestamp_cap() {
        let mut cfg = DetectionConfig::defaults();
        cfg.beaconing.min_observations = 5;
        cfg.beaconing.max_timestamps_per_flow = 4;

        assert!(cfg.validate().is_err());
    }
}
