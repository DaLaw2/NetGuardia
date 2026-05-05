use macros::config_settings;

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
