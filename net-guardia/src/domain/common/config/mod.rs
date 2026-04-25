pub mod acl;
pub mod constants;
pub mod correlation;
pub mod detection;
pub mod dns_filter;
pub mod ebpf;
pub mod health;
mod helpers;
pub mod http_server;
pub mod ml;
pub mod notification;
pub mod observability;
pub mod pipeline;
pub mod section;
pub mod soar;
pub mod suricata;
pub mod system;

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
use crate::domain::common::error::Error;
use crate::domain::common::error::system::SystemError;
use crate::interface::setting::SettingRepo;

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
    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let cfg = Self {
            acl: AclConfig::from_settings(repo)?,
            correlation: CorrelationConfig::from_settings(repo)?,
            detection: DetectionConfig::from_settings(repo)?,
            dns_filter: DnsFilterConfig::from_settings(repo)?,
            ebpf: EbpfConfig::from_settings(repo)?,
            health: HealthConfig::from_settings(repo)?,
            http_server: HttpServerConfig::from_settings(repo)?,
            ml: MlConfig::from_settings(repo)?,
            notification: NotificationConfig::from_settings(repo)?,
            observability: ObservabilityConfig::from_settings(repo)?,
            pipeline: PipelineConfig::from_settings(repo)?,
            soar: SoarConfig::from_settings(repo)?,
            suricata: SuricataConfig::from_settings(repo)?,
            system: SystemConfig::from_settings(repo)?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        AclConfig::seed_defaults(repo)?;
        CorrelationConfig::seed_defaults(repo)?;
        DetectionConfig::seed_defaults(repo)?;
        DnsFilterConfig::seed_defaults(repo)?;
        EbpfConfig::seed_defaults(repo)?;
        HealthConfig::seed_defaults(repo)?;
        HttpServerConfig::seed_defaults(repo)?;
        MlConfig::seed_defaults(repo)?;
        NotificationConfig::seed_defaults(repo)?;
        ObservabilityConfig::seed_defaults(repo)?;
        PipelineConfig::seed_defaults(repo)?;
        SoarConfig::seed_defaults(repo)?;
        SuricataConfig::seed_defaults(repo)?;
        SystemConfig::seed_defaults(repo)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        let valid = self.ebpf.refresh_interval <= 3600
            && self.ebpf.combined_queue_count > 0
            && self.ebpf.fill_queue_size > 0
            && self.ebpf.comp_queue_size > 0
            && self.ebpf.tx_queue_size > 0
            && self.ebpf.rx_queue_size > 0
            && self.ebpf.frame_size > 0
            && self.ebpf.frame_count > 0
            && self.http_server.port > 0
            && self.ml.max_concurrent_flows > 0
            && self.ml.min_packets_for_inference > 0
            && self.ml.min_packets_floor > 0
            && self.ml.inference_interval_secs > 0
            && self.ml.inference_batch_size > 0
            && self.ml.confirmation_window_fraction > 0
            && self.ml.drift_max_snapshots > 0
            && self.ml.drift_channel_capacity > 0
            && self.ml.alert_channel_capacity > 0
            && self.ml.traffic_logger_channel_capacity > 0
            && self.ml.circuit_breaker_threshold > 0
            && self.ml.onnx_load_timeout_secs > 0
            && self.ml.flow_max_packets_per_direction > 0
            && self.ml.flow_max_periods > 0
            && self.soar.handle_concurrency > 0
            && self.soar.rate_limit_cmd_channel_capacity > 0
            && self.soar.frequency_max_tracked_keys > 0
            && (0.0..=1.0).contains(&self.soar.default_rate_limit_factor)
            && (0.0..=1.0).contains(&self.soar.default_single_source_high_min_confidence)
            && self.detection.cleanup_interval_secs > 0
            && self.detection.fusion.max_dedup_entries > 0
            && self.detection.fusion.dedup_window_secs > 0
            && self.detection.beaconing.min_observations > 0
            && self.detection.beaconing.max_cache_entries > 0
            && self.correlation.max_tracked_entries > 0
            && self.correlation.scan.window_secs > 0
            && self.correlation.scan.threshold > 0
            && self.correlation.lateral.window_secs > 0
            && self.correlation.lateral.threshold > 0
            && self.correlation.botnet.window_secs > 0
            && self.correlation.botnet.threshold > 0
            && self.observability.log_buffer_capacity > 0
            && self.observability.log_buffer_max_message_bytes > 0
            && self.observability.log_live_default_limit > 0
            && self.observability.log_live_max_limit >= self.observability.log_live_default_limit
            && self.observability.fusion_explain_scan_limit > 0
            && self.observability.fusion_explain_response_cap > 0
            && self.observability.default_event_channel_capacity > 0
            && self.observability.drop_channel_capacity > 0
            && self.suricata.poll_interval_ms > 0
            && (0.0..=1.0).contains(&self.suricata.confidence_high)
            && (0.0..=1.0).contains(&self.suricata.confidence_medium)
            && (0.0..=1.0).contains(&self.suricata.confidence_low)
            && (0.0..=1.0).contains(&self.suricata.confidence_info);

        if !valid {
            Err(SystemError::InvalidConfig)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    fn test_db() -> Database {
        // SAFETY: in-memory SQLite open is infallible under standard library features.
        Database::new(":memory:").expect("in-memory DB")
    }

    #[test]
    fn defaults_are_valid() {
        let db = test_db();
        let cfg = AppConfig::from_settings(&db).expect("defaults should be valid");
        assert_eq!(cfg.http_server.port, 8080);
        assert_eq!(cfg.ebpf.ingress_ifname, "eth0");
        assert_eq!(cfg.ebpf.egress_ifname, "eth1");
        assert_eq!(cfg.ebpf.combined_queue_count, 1);
        assert_eq!(cfg.ebpf.frame_size, 4096);
        assert_eq!(cfg.http_server.jwt_expiry_hours, 24);
    }

    #[test]
    fn db_overrides_interface_names() {
        let db = test_db();
        db.set_setting("ingress_interface", "ens33").unwrap();
        db.set_setting("egress_interface", "ens34").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.ebpf.ingress_ifname, "ens33");
        assert_eq!(cfg.ebpf.egress_ifname, "ens34");
    }

    #[test]
    fn db_overrides_http_port() {
        let db = test_db();
        db.set_setting("http_port", "9090").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.http_server.port, 9090);
    }

    #[test]
    fn db_overrides_xdp_tuning() {
        let db = test_db();
        db.set_setting("frame_size", "8192").unwrap();
        db.set_setting("combined_queue_count", "4").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.ebpf.frame_size, 8192);
        assert_eq!(cfg.ebpf.combined_queue_count, 4);
    }

    #[test]
    fn invalid_db_values_ignored() {
        let db = test_db();
        db.set_setting("http_port", "not_a_number").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.http_server.port, 8080);
    }

    #[test]
    fn empty_db_uses_all_defaults() {
        let db = test_db();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.ml.inference_interval_secs, 5);
        assert_eq!(cfg.ml.inference_batch_size, 200);
        assert_eq!(cfg.system.database_path, "net-guardia.db");
    }

    #[test]
    fn seed_defaults_populates_empty_db() {
        let db = test_db();
        AppConfig::seed_defaults(&db).expect("seed should succeed");
        assert_eq!(db.get_setting("http_port").unwrap(), Some("8080".to_string()));
        assert_eq!(
            db.get_setting("traffic_logging_mode").unwrap(),
            Some("false".to_string())
        );
        assert_eq!(
            db.get_setting("pipeline_ingress").unwrap(),
            Some("access_control,rate_limit,service".to_string())
        );
        assert_eq!(
            db.get_setting("geoip_db_name").unwrap(),
            Some("net-guardia/static/geo/dbip-city-lite.mmdb".to_string())
        );
        assert_eq!(
            db.get_setting("soar_max_auto_block_cap").unwrap(),
            Some("100".to_string())
        );
        assert_eq!(db.get_setting("soar_max_ttl_secs").unwrap(), Some("86400".to_string()));
        assert_eq!(
            db.get_setting("ml_drift_window_secs").unwrap(),
            Some("3600".to_string())
        );
    }

    #[test]
    fn seed_defaults_does_not_overwrite_existing() {
        let db = test_db();
        db.set_setting("http_port", "9090").unwrap();
        AppConfig::seed_defaults(&db).expect("seed should succeed");
        assert_eq!(db.get_setting("http_port").unwrap(), Some("9090".to_string()));
    }

    #[test]
    fn db_overrides_traffic_logging_mode() {
        let db = test_db();
        db.set_setting("traffic_logging_mode", "true").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert!(cfg.ml.traffic_logging_mode);
    }

    #[test]
    fn default_traffic_logging_mode_is_false() {
        let db = test_db();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert!(!cfg.ml.traffic_logging_mode);
    }

    #[test]
    fn db_overrides_pipeline() {
        let db = test_db();
        db.set_setting("pipeline_ingress", "access_control,service").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.pipeline.ingress, vec!["access_control", "service"]);
    }

    #[test]
    fn db_overrides_soar_and_drift() {
        let db = test_db();
        db.set_setting("soar_max_ttl_secs", "3600").unwrap();
        db.set_setting("ml_drift_window_secs", "900").unwrap();
        let cfg = AppConfig::from_settings(&db).unwrap();
        assert_eq!(cfg.soar.max_ttl_secs, 3600);
        assert_eq!(cfg.ml.drift_window_secs, 900);
    }
}
