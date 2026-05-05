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

use std::collections::HashMap;

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
use crate::interface::config_repo::ConfigRepo;

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
    pub async fn from_config_repo(repo: &dyn ConfigRepo) -> Result<Self, Error> {
        let cfg = Self {
            acl: AclConfig::from_config_repo(repo).await?,
            correlation: CorrelationConfig::from_config_repo(repo).await?,
            detection: DetectionConfig::from_config_repo(repo).await?,
            dns_filter: DnsFilterConfig::from_config_repo(repo).await?,
            ebpf: EbpfConfig::from_config_repo(repo).await?,
            health: HealthConfig::from_config_repo(repo).await?,
            http_server: HttpServerConfig::from_config_repo(repo).await?,
            ml: MlConfig::from_config_repo(repo).await?,
            notification: NotificationConfig::from_config_repo(repo).await?,
            observability: ObservabilityConfig::from_config_repo(repo).await?,
            pipeline: PipelineConfig::from_config_repo(repo).await?,
            soar: SoarConfig::from_config_repo(repo).await?,
            suricata: SuricataConfig::from_config_repo(repo).await?,
            system: SystemConfig::from_config_repo(repo).await?,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub async fn seed_config_defaults(repo: &dyn ConfigRepo) -> Result<(), Error> {
        AclConfig::seed_config_defaults(repo).await?;
        CorrelationConfig::seed_config_defaults(repo).await?;
        DetectionConfig::seed_config_defaults(repo).await?;
        DnsFilterConfig::seed_config_defaults(repo).await?;
        EbpfConfig::seed_config_defaults(repo).await?;
        HealthConfig::seed_config_defaults(repo).await?;
        HttpServerConfig::seed_config_defaults(repo).await?;
        MlConfig::seed_config_defaults(repo).await?;
        NotificationConfig::seed_config_defaults(repo).await?;
        ObservabilityConfig::seed_config_defaults(repo).await?;
        PipelineConfig::seed_config_defaults(repo).await?;
        SoarConfig::seed_config_defaults(repo).await?;
        SuricataConfig::seed_config_defaults(repo).await?;
        SystemConfig::seed_config_defaults(repo).await?;
        Ok(())
    }

    pub fn api_setting_values(&self) -> HashMap<&'static str, String> {
        let mut values = HashMap::new();
        values.extend(self.acl.api_values());
        values.extend(self.correlation.api_values());
        values.extend(self.detection.api_values());
        values.extend(self.dns_filter.api_values());
        values.extend(self.ebpf.api_values());
        values.extend(self.http_server.api_values());
        values.extend(self.ml.api_values());
        values.extend(self.notification.api_values());
        values.extend(self.observability.api_values());
        values.extend(self.soar.api_values());
        values.extend(self.suricata.api_values());
        values
    }

    fn validate(&self) -> Result<(), Error> {
        let require = |ok: bool, field: &str| -> Result<(), Error> {
            if ok {
                Ok(())
            } else {
                Err(SystemError::InvalidConfigField(field))?
            }
        };

        require(self.ebpf.refresh_interval <= 3600, "ebpf.refresh_interval")?;
        require(self.ebpf.combined_queue_count > 0, "ebpf.combined_queue_count")?;
        require(self.ebpf.fill_queue_size > 0, "ebpf.fill_queue_size")?;
        require(self.ebpf.comp_queue_size > 0, "ebpf.comp_queue_size")?;
        require(self.ebpf.tx_queue_size > 0, "ebpf.tx_queue_size")?;
        require(self.ebpf.rx_queue_size > 0, "ebpf.rx_queue_size")?;
        require(self.ebpf.frame_size > 0, "ebpf.frame_size")?;
        require(self.ebpf.frame_count > 0, "ebpf.frame_count")?;
        require(
            self.ebpf.xsk_completion_batch_size > 0,
            "ebpf.xsk_completion_batch_size",
        )?;
        require(self.ebpf.xsk_rx_batch_size > 0, "ebpf.xsk_rx_batch_size")?;
        require(self.ebpf.xsk_tx_batch_size > 0, "ebpf.xsk_tx_batch_size")?;
        require(self.http_server.port > 0, "http_server.port")?;
        require(self.ml.max_concurrent_flows > 0, "ml.max_concurrent_flows")?;
        require(self.ml.min_packets_for_inference > 0, "ml.min_packets_for_inference")?;
        require(self.ml.min_packets_floor > 0, "ml.min_packets_floor")?;
        require(self.ml.inference_interval_secs > 0, "ml.inference_interval_secs")?;
        require(self.ml.inference_batch_size > 0, "ml.inference_batch_size")?;
        require(
            self.ml.confirmation_window_fraction > 0,
            "ml.confirmation_window_fraction",
        )?;
        require(self.ml.drift_max_snapshots > 0, "ml.drift_max_snapshots")?;
        require(self.ml.drift_channel_capacity > 0, "ml.drift_channel_capacity")?;
        require(self.ml.alert_channel_capacity > 0, "ml.alert_channel_capacity")?;
        require(
            self.ml.traffic_logger_channel_capacity > 0,
            "ml.traffic_logger_channel_capacity",
        )?;
        require(self.ml.circuit_breaker_threshold > 0, "ml.circuit_breaker_threshold")?;
        require(self.ml.onnx_load_timeout_secs > 0, "ml.onnx_load_timeout_secs")?;
        require(
            self.ml.flow_max_packets_per_direction > 0,
            "ml.flow_max_packets_per_direction",
        )?;
        require(self.ml.flow_max_periods > 0, "ml.flow_max_periods")?;
        require(self.soar.handle_concurrency > 0, "soar.handle_concurrency")?;
        require(
            self.soar.rate_limit_cmd_channel_capacity > 0,
            "soar.rate_limit_cmd_channel_capacity",
        )?;
        require(
            self.soar.frequency_max_tracked_keys > 0,
            "soar.frequency_max_tracked_keys",
        )?;
        require(self.soar.execution_list_limit > 0, "soar.execution_list_limit")?;
        require(
            self.soar.frequency_max_events_per_key > 0,
            "soar.frequency_max_events_per_key",
        )?;
        require(self.soar.frequency_retention_secs > 0, "soar.frequency_retention_secs")?;
        require(
            (0.0..=1.0).contains(&self.soar.default_rate_limit_factor),
            "soar.default_rate_limit_factor",
        )?;
        require(
            (0.0..=1.0).contains(&self.soar.default_single_source_high_min_confidence),
            "soar.default_single_source_high_min_confidence",
        )?;
        require(
            self.detection.cleanup_interval_secs > 0,
            "detection.cleanup_interval_secs",
        )?;
        require(
            self.detection.fusion.max_dedup_entries > 0,
            "detection.fusion.max_dedup_entries",
        )?;
        require(
            self.detection.fusion.source_count_max_entries > 0,
            "detection.fusion.source_count_max_entries",
        )?;
        require(
            self.detection.fusion.repeat_tracker_max_entries > 0,
            "detection.fusion.repeat_tracker_max_entries",
        )?;
        require(
            self.detection.fusion.dedup_window_secs > 0,
            "detection.fusion.dedup_window_secs",
        )?;
        require(
            self.detection.beaconing.min_observations > 0,
            "detection.beaconing.min_observations",
        )?;
        require(
            self.detection.beaconing.max_cache_entries > 0,
            "detection.beaconing.max_cache_entries",
        )?;
        require(
            self.detection.beaconing.max_timestamps_per_flow > 1,
            "detection.beaconing.max_timestamps_per_flow",
        )?;
        require(
            self.detection.flow_stats.max_snapshot_entries > 0,
            "detection.flow_stats.max_snapshot_entries",
        )?;
        require(
            self.detection.flow_stats.max_top_n >= self.detection.flow_stats.max_snapshot_entries,
            "detection.flow_stats.max_top_n",
        )?;
        require(
            self.health.monitoring_interval_secs > 0,
            "health.monitoring_interval_secs",
        )?;
        require(
            self.health.broadcast_channel_capacity > 0,
            "health.broadcast_channel_capacity",
        )?;
        require(
            self.correlation.max_tracked_entries > 0,
            "correlation.max_tracked_entries",
        )?;
        require(self.correlation.scan.window_secs > 0, "correlation.scan.window_secs")?;
        require(self.correlation.scan.threshold > 0, "correlation.scan.threshold")?;
        require(
            self.correlation.lateral.window_secs > 0,
            "correlation.lateral.window_secs",
        )?;
        require(self.correlation.lateral.threshold > 0, "correlation.lateral.threshold")?;
        require(
            self.correlation.botnet.window_secs > 0,
            "correlation.botnet.window_secs",
        )?;
        require(self.correlation.botnet.threshold > 0, "correlation.botnet.threshold")?;
        require(
            self.observability.log_buffer_capacity > 0,
            "observability.log_buffer_capacity",
        )?;
        require(
            self.observability.log_buffer_max_message_bytes > 0,
            "observability.log_buffer_max_message_bytes",
        )?;
        require(
            self.observability.log_live_default_limit > 0,
            "observability.log_live_default_limit",
        )?;
        require(
            self.observability.log_live_max_limit >= self.observability.log_live_default_limit,
            "observability.log_live_max_limit",
        )?;
        require(
            self.observability.fusion_explain_scan_limit > 0,
            "observability.fusion_explain_scan_limit",
        )?;
        require(
            self.observability.fusion_explain_response_cap > 0,
            "observability.fusion_explain_response_cap",
        )?;
        require(
            self.observability.default_event_channel_capacity > 0,
            "observability.default_event_channel_capacity",
        )?;
        require(
            self.observability.drop_channel_capacity > 0,
            "observability.drop_channel_capacity",
        )?;
        require(self.acl.geoip_cache_capacity > 0, "acl.geoip_cache_capacity")?;
        require(self.suricata.poll_interval_ms > 0, "suricata.poll_interval_ms")?;
        require(
            (0.0..=1.0).contains(&self.suricata.confidence_high),
            "suricata.confidence_high",
        )?;
        require(
            (0.0..=1.0).contains(&self.suricata.confidence_medium),
            "suricata.confidence_medium",
        )?;
        require(
            (0.0..=1.0).contains(&self.suricata.confidence_low),
            "suricata.confidence_low",
        )?;
        require(
            (0.0..=1.0).contains(&self.suricata.confidence_info),
            "suricata.confidence_info",
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    async fn test_db() -> Database {
        // SAFETY: in-memory SQLite open is infallible under standard library features.
        Database::new(":memory:").await.expect("in-memory DB")
    }

    #[tokio::test]
    async fn defaults_are_valid() {
        let db = test_db().await;
        let cfg = AppConfig::from_config_repo(&db)
            .await
            .expect("defaults should be valid");
        assert_eq!(cfg.http_server.port, 8080);
        assert_eq!(cfg.ebpf.ingress_ifname, "eth0");
        assert_eq!(cfg.ebpf.egress_ifname, "eth1");
        assert_eq!(cfg.ebpf.combined_queue_count, 1);
        assert_eq!(cfg.ebpf.frame_size, 4096);
        assert_eq!(cfg.ebpf.xsk_completion_batch_size, 256);
        assert_eq!(cfg.ebpf.xsk_rx_batch_size, 64);
        assert_eq!(cfg.ebpf.xsk_tx_batch_size, 64);
        assert_eq!(cfg.http_server.jwt_expiry_hours, 24);
    }

    #[tokio::test]
    async fn db_overrides_interface_names() {
        let db = test_db().await;
        db.set_config_value("ingress_interface", "ens33").await.unwrap();
        db.set_config_value("egress_interface", "ens34").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.ebpf.ingress_ifname, "ens33");
        assert_eq!(cfg.ebpf.egress_ifname, "ens34");
    }

    #[tokio::test]
    async fn db_overrides_http_port() {
        let db = test_db().await;
        db.set_config_value("http_port", "9090").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.http_server.port, 9090);
    }

    #[tokio::test]
    async fn db_overrides_xdp_tuning() {
        let db = test_db().await;
        db.set_config_value("frame_size", "8192").await.unwrap();
        db.set_config_value("combined_queue_count", "4").await.unwrap();
        db.set_config_value("xsk_completion_batch_size", "512").await.unwrap();
        db.set_config_value("xsk_rx_batch_size", "128").await.unwrap();
        db.set_config_value("xsk_tx_batch_size", "32").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.ebpf.frame_size, 8192);
        assert_eq!(cfg.ebpf.combined_queue_count, 4);
        assert_eq!(cfg.ebpf.xsk_completion_batch_size, 512);
        assert_eq!(cfg.ebpf.xsk_rx_batch_size, 128);
        assert_eq!(cfg.ebpf.xsk_tx_batch_size, 32);
    }

    #[tokio::test]
    async fn invalid_db_values_ignored() {
        let db = test_db().await;
        db.set_config_value("http_port", "not_a_number").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.http_server.port, 8080);
    }

    #[tokio::test]
    async fn empty_db_uses_all_defaults() {
        let db = test_db().await;
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.ml.inference_interval_secs, 5);
        assert_eq!(cfg.ml.inference_batch_size, 200);
        assert_eq!(cfg.system.database_path, "net-guardia.db");
    }

    #[tokio::test]
    async fn seed_config_defaults_populates_empty_db() {
        let db = test_db().await;
        AppConfig::seed_config_defaults(&db).await.expect("seed should succeed");
        assert_eq!(
            db.get_config_value("http_port").await.unwrap(),
            Some("8080".to_string())
        );
        assert_eq!(
            db.get_config_value("traffic_logging_mode").await.unwrap(),
            Some("false".to_string())
        );
        assert_eq!(
            db.get_config_value("pipeline_ingress").await.unwrap(),
            Some("access_control,rate_limit,service".to_string())
        );
        assert_eq!(
            db.get_config_value("geoip_db_path").await.unwrap(),
            Some("net-guardia/static/geo/dbip-city-lite.mmdb".to_string())
        );
        assert_eq!(
            db.get_config_value("soar_max_auto_block_cap").await.unwrap(),
            Some("100".to_string())
        );
        assert_eq!(
            db.get_config_value("soar_max_ttl_secs").await.unwrap(),
            Some("86400".to_string())
        );
        assert_eq!(
            db.get_config_value("soar_execution_list_limit").await.unwrap(),
            Some("100".to_string())
        );
        assert_eq!(
            db.get_config_value("ml_drift_window_secs").await.unwrap(),
            Some("3600".to_string())
        );
        assert_eq!(
            db.get_config_value("fusion_source_count_max_entries").await.unwrap(),
            Some("10000".to_string())
        );
        assert_eq!(
            db.get_config_value("fusion_repeat_tracker_max_entries").await.unwrap(),
            Some("5000".to_string())
        );
        assert_eq!(
            db.get_config_value("health_broadcast_channel_capacity").await.unwrap(),
            Some("100".to_string())
        );
        assert_eq!(
            db.get_config_value("geoip_cache_capacity").await.unwrap(),
            Some("10000".to_string())
        );
    }

    #[tokio::test]
    async fn seed_config_defaults_does_not_overwrite_existing() {
        let db = test_db().await;
        db.set_config_value("http_port", "9090").await.unwrap();
        AppConfig::seed_config_defaults(&db).await.expect("seed should succeed");
        assert_eq!(
            db.get_config_value("http_port").await.unwrap(),
            Some("9090".to_string())
        );
    }

    #[tokio::test]
    async fn db_overrides_traffic_logging_mode() {
        let db = test_db().await;
        db.set_config_value("traffic_logging_mode", "true").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert!(cfg.ml.traffic_logging_mode);
    }

    #[tokio::test]
    async fn default_traffic_logging_mode_is_false() {
        let db = test_db().await;
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert!(!cfg.ml.traffic_logging_mode);
    }

    #[tokio::test]
    async fn db_overrides_pipeline() {
        let db = test_db().await;
        db.set_config_value("pipeline_ingress", "access_control,service")
            .await
            .unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.pipeline.ingress, vec!["access_control", "service"]);
    }

    #[tokio::test]
    async fn db_overrides_soar_and_drift() {
        let db = test_db().await;
        db.set_config_value("soar_max_ttl_secs", "3600").await.unwrap();
        db.set_config_value("soar_execution_list_limit", "42").await.unwrap();
        db.set_config_value("ml_drift_window_secs", "900").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.soar.max_ttl_secs, 3600);
        assert_eq!(cfg.soar.execution_list_limit, 42);
        assert_eq!(cfg.ml.drift_window_secs, 900);
    }

    #[tokio::test]
    async fn db_overrides_fusion_runtime_cache_sizes() {
        let db = test_db().await;
        db.set_config_value("fusion_source_count_max_entries", "1234")
            .await
            .unwrap();
        db.set_config_value("fusion_repeat_tracker_max_entries", "567")
            .await
            .unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.detection.fusion.source_count_max_entries, 1234);
        assert_eq!(cfg.detection.fusion.repeat_tracker_max_entries, 567);
    }

    #[tokio::test]
    async fn db_overrides_health_runtime_values() {
        let db = test_db().await;
        db.set_config_value("health_monitoring_interval_secs", "9")
            .await
            .unwrap();
        db.set_config_value("health_broadcast_channel_capacity", "321")
            .await
            .unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.health.monitoring_interval_secs, 9);
        assert_eq!(cfg.health.broadcast_channel_capacity, 321);
    }

    #[tokio::test]
    async fn db_overrides_geoip_runtime_cache_capacity() {
        let db = test_db().await;
        db.set_config_value("geoip_cache_capacity", "2048").await.unwrap();
        let cfg = AppConfig::from_config_repo(&db).await.unwrap();
        assert_eq!(cfg.acl.geoip_cache_capacity, 2048);
    }
}
