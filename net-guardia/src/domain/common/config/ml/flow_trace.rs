use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "flow_trace")]
#[derive(Debug, Clone)]
pub struct FlowTraceConfig {
    #[setting(key = "flow_trace_max_file_bytes", default = "524288000")]
    pub max_file_bytes: u64,
    #[setting(key = "flow_trace_max_file_age_secs", default = "3600")]
    pub max_file_age_secs: u64,
    #[setting(key = "flow_trace_total_budget_bytes", default = "10737418240")]
    pub total_budget_bytes: u64,
    #[setting(key = "traffic_logger_channel_capacity", default = "65536")]
    pub traffic_logger_channel_capacity: usize,
}

impl FlowTraceConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_file_bytes > 0, "ml.flow_trace.max_file_bytes")?;
        require_config_field(self.max_file_age_secs > 0, "ml.flow_trace.max_file_age_secs")?;
        require_config_field(
            self.total_budget_bytes >= self.max_file_bytes,
            "ml.flow_trace.total_budget_bytes",
        )?;
        require_config_field(
            self.traffic_logger_channel_capacity > 0,
            "ml.flow_trace.traffic_logger_channel_capacity",
        )
    }
}
