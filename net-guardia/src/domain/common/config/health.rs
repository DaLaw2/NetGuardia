use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "health")]
#[derive(Debug, Clone)]
pub struct HealthConfig {
    #[setting(key = "health_cpu_issue_percent", default = "90.0")]
    pub cpu_issue_percent: f32,
    #[setting(key = "health_cpu_warn_percent", default = "75.0")]
    pub cpu_warn_percent: f32,
    #[setting(key = "health_mem_issue_percent", default = "95.0")]
    pub mem_issue_percent: f32,
    #[setting(key = "health_mem_warn_percent", default = "80.0")]
    pub mem_warn_percent: f32,
    #[setting(key = "health_disk_issue_percent", default = "95.0")]
    pub disk_issue_percent: f32,
    #[setting(key = "health_disk_warn_percent", default = "90.0")]
    pub disk_warn_percent: f32,
    #[setting(key = "health_temp_issue_celsius", default = "80.0")]
    pub temp_issue_celsius: f32,
    #[setting(key = "health_temp_warn_celsius", default = "70.0")]
    pub temp_warn_celsius: f32,
    #[setting(key = "health_monitoring_interval_secs", default = "5")]
    pub monitoring_interval_secs: u64,
    #[setting(key = "health_broadcast_channel_capacity", default = "100")]
    pub broadcast_channel_capacity: usize,
}

impl HealthConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.monitoring_interval_secs > 0, "health.monitoring_interval_secs")?;
        require_config_field(self.broadcast_channel_capacity > 0, "health.broadcast_channel_capacity")?;
        require_config_field(
            (0.0..=100.0).contains(&self.cpu_warn_percent),
            "health.cpu_warn_percent",
        )?;
        require_config_field(
            (0.0..=100.0).contains(&self.cpu_issue_percent),
            "health.cpu_issue_percent",
        )?;
        require_config_field(
            self.cpu_warn_percent <= self.cpu_issue_percent,
            "health.cpu_warn_percent",
        )?;
        require_config_field(
            (0.0..=100.0).contains(&self.mem_warn_percent),
            "health.mem_warn_percent",
        )?;
        require_config_field(
            (0.0..=100.0).contains(&self.mem_issue_percent),
            "health.mem_issue_percent",
        )?;
        require_config_field(
            self.mem_warn_percent <= self.mem_issue_percent,
            "health.mem_warn_percent",
        )?;
        require_config_field(
            (0.0..=100.0).contains(&self.disk_warn_percent),
            "health.disk_warn_percent",
        )?;
        require_config_field(
            (0.0..=100.0).contains(&self.disk_issue_percent),
            "health.disk_issue_percent",
        )?;
        require_config_field(
            self.disk_warn_percent <= self.disk_issue_percent,
            "health.disk_warn_percent",
        )?;
        require_config_field(
            self.temp_warn_celsius <= self.temp_issue_celsius,
            "health.temp_warn_celsius",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::HealthConfig;

    #[test]
    fn percentage_thresholds_are_bounded_and_ordered() {
        let invalid_cases: [fn(&mut HealthConfig); 10] = [
            |cfg: &mut HealthConfig| cfg.cpu_warn_percent = -1.0,
            |cfg: &mut HealthConfig| cfg.cpu_issue_percent = 101.0,
            |cfg: &mut HealthConfig| cfg.mem_warn_percent = -1.0,
            |cfg: &mut HealthConfig| cfg.mem_issue_percent = 101.0,
            |cfg: &mut HealthConfig| cfg.disk_warn_percent = -1.0,
            |cfg: &mut HealthConfig| cfg.disk_issue_percent = 101.0,
            |cfg: &mut HealthConfig| {
                cfg.cpu_warn_percent = 90.0;
                cfg.cpu_issue_percent = 80.0;
            },
            |cfg: &mut HealthConfig| {
                cfg.mem_warn_percent = 90.0;
                cfg.mem_issue_percent = 80.0;
            },
            |cfg: &mut HealthConfig| {
                cfg.disk_warn_percent = 90.0;
                cfg.disk_issue_percent = 80.0;
            },
            |cfg: &mut HealthConfig| {
                cfg.temp_warn_celsius = 90.0;
                cfg.temp_issue_celsius = 80.0;
            },
        ];

        for apply_invalid in invalid_cases {
            let mut cfg = HealthConfig::defaults();
            apply_invalid(&mut cfg);

            assert!(cfg.validate().is_err());
        }
    }
}
