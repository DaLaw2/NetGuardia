use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "ml")]
#[derive(Debug, Clone)]
pub struct DriftConfig {
    #[setting(key = "ml_drift_window_secs", default = "3600")]
    pub window_secs: u64,
    #[setting(key = "ml_drift_max_snapshots", default = "10000")]
    pub max_snapshots: usize,
    #[setting(key = "ml_drift_channel_capacity", default = "1024")]
    pub channel_capacity: usize,
}

impl DriftConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.window_secs > 0, "ml.drift.window_secs")?;
        require_config_field(self.max_snapshots > 0, "ml.drift.max_snapshots")?;
        require_config_field(self.channel_capacity > 0, "ml.drift.channel_capacity")
    }
}
