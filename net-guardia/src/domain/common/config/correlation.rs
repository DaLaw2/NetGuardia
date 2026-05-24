use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[derive(Debug, Clone)]
pub struct CorrelationDetectorParams {
    pub window_secs: u64,
    pub threshold: usize,
}

#[config_settings(section = "correlation")]
#[setting(key = "correlation_scan_window_secs", default = "120", path = "scan.window_secs")]
#[setting(key = "correlation_scan_threshold", default = "20", path = "scan.threshold")]
#[setting(
    key = "correlation_lateral_window_secs",
    default = "300",
    path = "lateral.window_secs"
)]
#[setting(key = "correlation_lateral_threshold", default = "5", path = "lateral.threshold")]
#[setting(key = "correlation_botnet_window_secs", default = "300", path = "botnet.window_secs")]
#[setting(key = "correlation_botnet_threshold", default = "10", path = "botnet.threshold")]
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub scan: CorrelationDetectorParams,
    pub lateral: CorrelationDetectorParams,
    pub botnet: CorrelationDetectorParams,
    #[setting(key = "correlation_max_tracked_entries", default = "10000")]
    pub max_tracked_entries: usize,
}

impl CorrelationConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_tracked_entries > 0, "correlation.max_tracked_entries")?;
        self.scan.validate("correlation.scan")?;
        self.lateral.validate("correlation.lateral")?;
        self.botnet.validate("correlation.botnet")
    }
}

impl CorrelationDetectorParams {
    fn validate(&self, prefix: &str) -> Result<(), Error> {
        require_config_field(self.window_secs > 0, &format!("{prefix}.window_secs"))?;
        require_config_field(self.threshold > 0, &format!("{prefix}.threshold"))
    }
}
