use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "ml")]
#[derive(Debug, Clone)]
pub struct FlowConfig {
    #[setting(key = "ml_flow_max_packets_per_direction", default = "1000")]
    pub max_packets_per_direction: usize,
    #[setting(key = "ml_flow_max_periods", default = "1000")]
    pub max_periods: usize,
    #[setting(key = "ml_flow_idle_threshold_us", default = "1000000")]
    pub idle_threshold_us: u64,
    #[setting(key = "ml_flow_bulk_min_packets", default = "4")]
    pub bulk_min_packets: u64,
    #[setting(key = "ml_flow_bulk_min_bytes", default = "1000")]
    pub bulk_min_bytes: u64,
    #[setting(key = "ml_flow_idle_timeout_us", default = "120000000")]
    pub idle_timeout_us: u64,
    #[setting(key = "ml_flow_terminated_timeout_us", default = "5000000")]
    pub terminated_timeout_us: u64,
}

impl FlowConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_packets_per_direction > 0, "ml.flow.max_packets_per_direction")?;
        require_config_field(self.max_periods > 0, "ml.flow.max_periods")?;
        require_config_field(self.idle_threshold_us > 0, "ml.flow.idle_threshold_us")?;
        require_config_field(self.bulk_min_packets > 0, "ml.flow.bulk_min_packets")?;
        require_config_field(self.bulk_min_bytes > 0, "ml.flow.bulk_min_bytes")?;
        require_config_field(self.idle_timeout_us > 0, "ml.flow.idle_timeout_us")?;
        require_config_field(self.terminated_timeout_us > 0, "ml.flow.terminated_timeout_us")
    }
}
