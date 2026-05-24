pub mod acl;
pub mod constants;
pub mod correlation;
pub mod detection;
pub mod dns_filter;
pub mod ebpf;
pub mod health;
pub mod http_server;
pub mod ml;
pub mod notification;
pub mod observability;
pub mod pipeline;
pub mod section;
pub mod soar;
pub mod suricata;
pub mod system;

use std::collections::HashMap;

use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::domain::common::config::acl::AclConfig;
use crate::domain::common::config::correlation::CorrelationConfig;
use crate::domain::common::config::detection::DetectionConfig;
use crate::domain::common::config::dns_filter::DnsFilterConfig;
use crate::domain::common::config::ebpf::EbpfConfig;
use crate::domain::common::config::health::HealthConfig;
use crate::domain::common::config::http_server::HttpServerConfig;
use crate::domain::common::config::ml::MlConfig;
use crate::domain::common::config::notification::NotificationConfig;
use crate::domain::common::config::observability::ObservabilityConfig;
use crate::domain::common::config::pipeline::PipelineConfig;
use crate::domain::common::config::soar::SoarConfig;
use crate::domain::common::config::suricata::SuricataConfig;
use crate::domain::common::config::system::SystemConfig;

pub type ConfigValues = HashMap<String, String>;

pub fn require_config_field(ok: bool, field: &str) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(SystemError::InvalidConfigField(field))?
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub acl: AclConfig,
    pub correlation: CorrelationConfig,
    pub detection: DetectionConfig,
    pub dns_filter: DnsFilterConfig,
    pub ebpf: EbpfConfig,
    pub health: HealthConfig,
    pub http_server: HttpServerConfig,
    pub ml: MlConfig,
    pub notification: NotificationConfig,
    pub observability: ObservabilityConfig,
    pub pipeline: PipelineConfig,
    pub soar: SoarConfig,
    pub suricata: SuricataConfig,
    pub system: SystemConfig,
}

impl AppConfig {
    pub fn defaults() -> Self {
        Self {
            acl: AclConfig::defaults(),
            correlation: CorrelationConfig::defaults(),
            detection: DetectionConfig::defaults(),
            dns_filter: DnsFilterConfig::defaults(),
            ebpf: EbpfConfig::defaults(),
            health: HealthConfig::defaults(),
            http_server: HttpServerConfig::defaults(),
            ml: MlConfig::defaults(),
            notification: NotificationConfig::defaults(),
            observability: ObservabilityConfig::defaults(),
            pipeline: PipelineConfig::defaults(),
            soar: SoarConfig::defaults(),
            suricata: SuricataConfig::defaults(),
            system: SystemConfig::defaults(),
        }
    }

    pub fn from_config_values(values: &ConfigValues) -> Result<Self, Error> {
        SystemConfig::validate_config_values(values)?;
        let mut cfg = Self::defaults();
        cfg.apply_config_values(values);
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn apply_config_values(&mut self, values: &ConfigValues) {
        self.acl.apply_config_values(values);
        self.correlation.apply_config_values(values);
        self.detection.apply_config_values(values);
        self.dns_filter.apply_config_values(values);
        self.ebpf.apply_config_values(values);
        self.health.apply_config_values(values);
        self.http_server.apply_config_values(values);
        self.ml.apply_config_values(values);
        self.notification.apply_config_values(values);
        self.observability.apply_config_values(values);
        self.pipeline.apply_config_values(values);
        self.soar.apply_config_values(values);
        self.suricata.apply_config_values(values);
        self.system.apply_config_values(values);
    }

    pub fn default_settings() -> Vec<(&'static str, String)> {
        let mut settings = Vec::new();
        settings.extend(AclConfig::default_settings());
        settings.extend(CorrelationConfig::default_settings());
        settings.extend(DetectionConfig::default_settings());
        settings.extend(DnsFilterConfig::default_settings());
        settings.extend(EbpfConfig::default_settings());
        settings.extend(HealthConfig::default_settings());
        settings.extend(HttpServerConfig::default_settings());
        settings.extend(MlConfig::default_settings());
        settings.extend(NotificationConfig::default_settings());
        settings.extend(ObservabilityConfig::default_settings());
        settings.extend(PipelineConfig::default_settings());
        settings.extend(SoarConfig::default_settings());
        settings.extend(SuricataConfig::default_settings());
        settings.extend(SystemConfig::default_settings());
        settings
    }

    pub fn api_setting_values(&self) -> HashMap<&'static str, String> {
        let mut values = HashMap::new();
        values.extend(self.acl.api_values());
        values.extend(self.correlation.api_values());
        values.extend(self.detection.api_values());
        values.extend(self.dns_filter.api_values());
        values.extend(self.ebpf.api_values());
        values.extend(self.health.api_values());
        values.extend(self.http_server.api_values());
        values.extend(self.ml.api_values());
        values.extend(self.notification.api_values());
        values.extend(self.observability.api_values());
        values.extend(self.pipeline.api_values());
        values.extend(self.soar.api_values());
        values.extend(self.suricata.api_values());
        values.extend(self.system.api_values());
        values
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.acl.validate()?;
        self.correlation.validate()?;
        self.detection.validate()?;
        self.dns_filter.validate()?;
        self.ebpf.validate()?;
        self.health.validate()?;
        self.http_server.validate()?;
        self.ml.validate()?;
        self.notification.validate()?;
        self.observability.validate()?;
        self.pipeline.validate()?;
        self.soar.validate()?;
        self.suricata.validate()?;
        self.system.validate()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::AppConfig;

    #[test]
    fn defaults_are_valid() {
        let cfg = AppConfig::defaults();

        cfg.validate().expect("defaults should be valid");
        assert_eq!(cfg.http_server.port, 8080);
        assert_eq!(cfg.ebpf.ingress_ifname, "eth0");
        assert_eq!(cfg.ebpf.egress_ifname, "eth1");
        assert_eq!(cfg.http_server.session_expiry_hours, 24);
        assert_eq!(cfg.http_server.session_idle_timeout_minutes, 30);
    }

    #[test]
    fn config_values_override_defaults_without_repo_access() {
        let values = HashMap::from([
            ("http_port".to_string(), "9090".to_string()),
            ("traffic_logging_mode".to_string(), "true".to_string()),
            ("pipeline_ingress".to_string(), "access_control,service".to_string()),
        ]);

        let cfg = AppConfig::from_config_values(&values).expect("config from values");

        assert_eq!(cfg.http_server.port, 9090);
        assert!(cfg.ml.inference.traffic_logging_mode);
        assert_eq!(cfg.pipeline.ingress, vec!["access_control", "service"]);
    }

    #[test]
    fn invalid_config_values_are_ignored() {
        let values = HashMap::from([("http_port".to_string(), "not-a-number".to_string())]);

        let cfg = AppConfig::from_config_values(&values).expect("config from values");

        assert_eq!(cfg.http_server.port, 8080);
    }

    #[test]
    fn api_setting_values_include_all_api_visible_config_sections() {
        let values = AppConfig::defaults().api_setting_values();

        assert!(values.contains_key("health_monitoring_interval_secs"));
        assert!(values.contains_key("enforce_mode"));
        assert!(!values.contains_key("pipeline_ingress"));
    }
}
