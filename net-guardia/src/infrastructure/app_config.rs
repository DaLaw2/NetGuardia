use crate::adapter::persistence::Database;
use crate::model::error::Error;
use crate::model::error::system::SystemError;
use crate::model::system::config::{
    HttpConfig, InferenceConfig, MiscConfig, NetworkConfig, PipelineConfig, SuricataConfig,
};

pub struct AppConfig {
    pub http: HttpConfig,
    pub network: NetworkConfig,
    pub inference: InferenceConfig,
    pub misc: MiscConfig,
    pub pipeline: PipelineConfig,
    pub suricata: SuricataConfig,
}

impl AppConfig {
    /// Build AppConfig from DB settings with hardcoded defaults.
    /// DB is the single source of truth — config.toml is not read.
    pub fn new(db: &Database) -> Result<Self, Error> {
        let mut config = Self::defaults();
        Self::apply_db_overrides(&mut config, db);
        Self::validate_config(&config)?;
        Ok(config)
    }

    /// Seed all default values into the settings table.
    /// Uses INSERT OR IGNORE so existing user-set values are never overwritten.
    /// Call this before `new()` so the DB always has a complete set of keys.
    pub fn seed_defaults(db: &Database) -> Result<(), Error> {
        let defaults: &[(&str, String)] = &[
            // Network
            ("ingress_interface", "eth0".into()),
            ("egress_interface", "eth1".into()),
            ("combined_queue_count", "1".into()),
            ("channel_size", "4096".into()),
            ("fill_queue_size", "4096".into()),
            ("comp_queue_size", "4096".into()),
            ("tx_queue_size", "4096".into()),
            ("rx_queue_size", "4096".into()),
            ("frame_size", "4096".into()),
            ("frame_count", "4096".into()),
            ("refresh_interval", "5".into()),
            ("packet_buffer_size", "2048".into()),
            ("buffer_pool_capacity", "1024".into()),
            // HTTP
            ("http_port", "8080".into()),
            ("jwt_expiry_hours", "24".into()),
            ("cors_allowed_origins", "".into()),
            // Inference
            ("deep_autoencoder_name", "deep_autoencoder.onnx".into()),
            ("classifier_name", "classifier.onnx".into()),
            ("models_config_name", "inference_config.json".into()),
            ("max_concurrent_flows", "10000".into()),
            ("min_packets_for_inference", "5".into()),
            ("inference_interval_secs", "5".into()),
            ("aggregator_window_secs", "30".into()),
            ("inference_batch_size", "200".into()),
            ("traffic_logging_mode", "false".into()),
            ("traffic_log_csv_path", "traffic_log.csv".into()),
            // Flow Trace rotation (defaults match the DEFAULT_* constants
            // in traffic_logger.rs; DB overrides let admins tune per env).
            ("flow_trace_max_file_bytes", (500 * 1024 * 1024_u64).to_string()),
            ("flow_trace_max_file_age_secs", "3600".into()),
            (
                "flow_trace_total_budget_bytes",
                (10 * 1024 * 1024 * 1024_u64).to_string(),
            ),
            // Model upload size caps (per-field multipart ceilings).
            ("model_upload_max_onnx_bytes", (100 * 1024 * 1024_usize).to_string()),
            ("model_upload_max_manifest_bytes", (64 * 1024_usize).to_string()),
            ("model_upload_max_scaler_bytes", (64 * 1024_usize).to_string()),
            // Misc
            ("geoip_db_name", "net-guardia/static/geo/dbip-city-lite.mmdb".into()),
            // Pipeline
            ("pipeline_ingress", "access_control,rate_limit,service".into()),
            ("pipeline_egress", "".into()),
            // SOAR
            ("soar_max_auto_block_cap", "100".into()),
            ("soar_max_ttl_secs", "86400".into()),
            // ML
            ("ml_drift_window_secs", "3600".into()),
            // Telegram
            ("telegram_rate_limit_max_messages", "20".into()),
            ("telegram_rate_limit_window_secs", "60".into()),
            // Directories
            ("report_dir", "/var/lib/netguardia/reports".into()),
            ("log_dir", "logs".into()),
            // DNS
            ("dns_max_domains_per_request", "1000".into()),
            // HTTPS redirect
            ("force_https", "false".into()),
            // Suricata bridge
            ("suricata_enabled", "false".into()),
            ("suricata_binary_path", "/usr/bin/suricata".into()),
            ("suricata_config_path", "/etc/netguardia/suricata.yaml".into()),
            ("suricata_eve_log_path", "/var/log/netguardia/eve.json".into()),
            ("suricata_auto_restart_on_crash", "true".into()),
            ("suricata_restart_backoff_secs", "10".into()),
        ];

        for (key, value) in defaults {
            if db.get_setting(key)?.is_none() {
                db.set_setting(key, value)?;
            }
        }
        Ok(())
    }

    /// Hardcoded defaults for all configuration values.
    /// These match the original config.toml values and serve as the baseline
    /// when DB has no overrides (e.g., first boot before setup wizard).
    fn defaults() -> Self {
        Self {
            http: HttpConfig {
                http_server_bind_port: 8080,
                jwt_expiry_hours: 24,
                cors_allowed_origins: vec![],
            },
            network: NetworkConfig {
                ingress_ifname: "eth0".into(),
                egress_ifname: "eth1".into(),
                combined_queue_count: 1,
                channel_size: 4096,
                fill_queue_size: 4096,
                comp_queue_size: 4096,
                tx_queue_size: 4096,
                rx_queue_size: 4096,
                frame_size: 4096,
                frame_count: 4096,
                refresh_interval: 5,
                packet_buffer_size: 2048,
                buffer_pool_capacity: 1024,
            },
            inference: InferenceConfig {
                deep_autoencoder_name: "deep_autoencoder.onnx".into(),
                classifier_name: "classifier.onnx".into(),
                models_config_name: "inference_config.json".into(),
                max_concurrent_flows: 10000,
                min_packets_for_inference: 5,
                inference_interval_secs: 5,
                aggregator_window_secs: 30,
                inference_batch_size: 200,
                traffic_logging_mode: false,
                traffic_log_csv_path: "traffic_log.csv".into(),
                flow_trace_max_file_bytes: 500 * 1024 * 1024,
                flow_trace_max_file_age_secs: 3600,
                flow_trace_total_budget_bytes: 10 * 1024 * 1024 * 1024,
                model_upload_max_onnx_bytes: 100 * 1024 * 1024,
                model_upload_max_manifest_bytes: 64 * 1024,
                model_upload_max_scaler_bytes: 64 * 1024,
            },
            misc: MiscConfig {
                geoip_db_name: "net-guardia/static/geo/dbip-city-lite.mmdb".into(),
                database_path: "net-guardia.db".into(),
            },
            pipeline: PipelineConfig {
                ingress: vec!["access_control".into(), "rate_limit".into(), "service".into()],
                egress: vec![],
            },
            suricata: SuricataConfig {
                enabled: false,
                binary_path: "/usr/bin/suricata".into(),
                config_path: "/etc/netguardia/suricata.yaml".into(),
                eve_log_path: "/var/log/netguardia/eve.json".into(),
                auto_restart_on_crash: true,
                restart_backoff_secs: 10,
            },
        }
    }

    /// Override defaults with DB settings. Each setting is optional —
    /// missing keys simply keep the default value.
    fn apply_db_overrides(config: &mut Self, db: &Database) {
        // Network interfaces (set by setup wizard)
        if let Ok(Some(v)) = db.get_setting("ingress_interface") {
            config.network.ingress_ifname = v;
        }
        if let Ok(Some(v)) = db.get_setting("egress_interface") {
            config.network.egress_ifname = v;
        }

        // HTTP
        if let Ok(Some(v)) = db.get_setting("http_port")
            && let Ok(port) = v.parse::<u16>()
        {
            config.http.http_server_bind_port = port;
        }
        if let Ok(Some(v)) = db.get_setting("jwt_expiry_hours")
            && let Ok(hours) = v.parse::<u64>()
        {
            config.http.jwt_expiry_hours = hours;
        }
        if let Ok(Some(v)) = db.get_setting("cors_allowed_origins") {
            config.http.cors_allowed_origins = if v.is_empty() {
                vec![]
            } else {
                v.split(',').map(|s| s.trim().to_string()).collect()
            };
        }

        // XDP tuning
        if let Ok(Some(v)) = db.get_setting("combined_queue_count")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.combined_queue_count = n;
        }
        if let Ok(Some(v)) = db.get_setting("fill_queue_size")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.fill_queue_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("comp_queue_size")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.comp_queue_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("tx_queue_size")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.tx_queue_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("rx_queue_size")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.rx_queue_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("frame_size")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.frame_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("frame_count")
            && let Ok(n) = v.parse::<u32>()
        {
            config.network.frame_count = n;
        }

        // Inference tuning
        if let Ok(Some(v)) = db.get_setting("max_concurrent_flows")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.max_concurrent_flows = n;
        }
        if let Ok(Some(v)) = db.get_setting("min_packets_for_inference")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.min_packets_for_inference = n;
        }
        if let Ok(Some(v)) = db.get_setting("inference_interval_secs")
            && let Ok(n) = v.parse::<u64>()
        {
            config.inference.inference_interval_secs = n;
        }
        if let Ok(Some(v)) = db.get_setting("aggregator_window_secs")
            && let Ok(n) = v.parse::<u64>()
        {
            config.inference.aggregator_window_secs = n;
        }
        if let Ok(Some(v)) = db.get_setting("inference_batch_size")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.inference_batch_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("flow_trace_max_file_bytes")
            && let Ok(n) = v.parse::<u64>()
        {
            config.inference.flow_trace_max_file_bytes = n;
        }
        if let Ok(Some(v)) = db.get_setting("flow_trace_max_file_age_secs")
            && let Ok(n) = v.parse::<u64>()
        {
            config.inference.flow_trace_max_file_age_secs = n;
        }
        if let Ok(Some(v)) = db.get_setting("flow_trace_total_budget_bytes")
            && let Ok(n) = v.parse::<u64>()
        {
            config.inference.flow_trace_total_budget_bytes = n;
        }
        if let Ok(Some(v)) = db.get_setting("model_upload_max_onnx_bytes")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.model_upload_max_onnx_bytes = n;
        }
        if let Ok(Some(v)) = db.get_setting("model_upload_max_manifest_bytes")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.model_upload_max_manifest_bytes = n;
        }
        if let Ok(Some(v)) = db.get_setting("model_upload_max_scaler_bytes")
            && let Ok(n) = v.parse::<usize>()
        {
            config.inference.model_upload_max_scaler_bytes = n;
        }
        if let Ok(Some(v)) = db.get_setting("refresh_interval")
            && let Ok(n) = v.parse::<u64>()
        {
            config.network.refresh_interval = n;
        }
        if let Ok(Some(v)) = db.get_setting("channel_size")
            && let Ok(n) = v.parse::<usize>()
        {
            config.network.channel_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("packet_buffer_size")
            && let Ok(n) = v.parse::<usize>()
        {
            config.network.packet_buffer_size = n;
        }
        if let Ok(Some(v)) = db.get_setting("buffer_pool_capacity")
            && let Ok(n) = v.parse::<usize>()
        {
            config.network.buffer_pool_capacity = n;
        }

        // Bool settings
        if let Ok(Some(v)) = db.get_setting("traffic_logging_mode") {
            config.inference.traffic_logging_mode = v == "true" || v == "1";
        }

        // File path settings
        if let Ok(Some(v)) = db.get_setting("deep_autoencoder_name")
            && !v.is_empty()
        {
            config.inference.deep_autoencoder_name = v;
        }
        if let Ok(Some(v)) = db.get_setting("classifier_name")
            && !v.is_empty()
        {
            config.inference.classifier_name = v;
        }
        if let Ok(Some(v)) = db.get_setting("models_config_name")
            && !v.is_empty()
        {
            config.inference.models_config_name = v;
        }
        if let Ok(Some(v)) = db.get_setting("traffic_log_csv_path")
            && !v.is_empty()
        {
            config.inference.traffic_log_csv_path = v;
        }
        if let Ok(Some(v)) = db.get_setting("geoip_db_name")
            && !v.is_empty()
        {
            config.misc.geoip_db_name = v;
        }

        // Suricata bridge
        if let Ok(Some(v)) = db.get_setting("suricata_enabled") {
            config.suricata.enabled = v == "true" || v == "1";
        }
        if let Ok(Some(v)) = db.get_setting("suricata_binary_path")
            && !v.is_empty()
        {
            config.suricata.binary_path = v;
        }
        if let Ok(Some(v)) = db.get_setting("suricata_config_path")
            && !v.is_empty()
        {
            config.suricata.config_path = v;
        }
        if let Ok(Some(v)) = db.get_setting("suricata_eve_log_path")
            && !v.is_empty()
        {
            config.suricata.eve_log_path = v;
        }
        if let Ok(Some(v)) = db.get_setting("suricata_auto_restart_on_crash") {
            config.suricata.auto_restart_on_crash = v == "true" || v == "1";
        }
        if let Ok(Some(v)) = db.get_setting("suricata_restart_backoff_secs")
            && let Ok(n) = v.parse::<u64>()
        {
            config.suricata.restart_backoff_secs = n;
        }

        // Pipeline (stored as comma-separated)
        if let Ok(Some(v)) = db.get_setting("pipeline_ingress") {
            config.pipeline.ingress = if v.is_empty() {
                vec![]
            } else {
                v.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
        if let Ok(Some(v)) = db.get_setting("pipeline_egress") {
            config.pipeline.egress = if v.is_empty() {
                vec![]
            } else {
                v.split(',').map(|s| s.trim().to_string()).collect()
            };
        }
    }

    fn validate_config(config: &Self) -> Result<(), Error> {
        let net = &config.network;
        let inf = &config.inference;
        let valid = net.refresh_interval <= 3600
            && net.combined_queue_count > 0
            && net.fill_queue_size > 0
            && net.comp_queue_size > 0
            && net.tx_queue_size > 0
            && net.rx_queue_size > 0
            && net.frame_size > 0
            && net.frame_count > 0
            && config.http.http_server_bind_port > 0
            && inf.max_concurrent_flows > 0
            && inf.min_packets_for_inference > 0
            && inf.inference_interval_secs > 0
            && inf.inference_batch_size > 0;

        if !valid {
            Err(SystemError::InvalidConfig)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::new(":memory:").expect("in-memory DB")
    }

    #[test]
    fn defaults_are_valid() {
        let db = test_db();
        let config = AppConfig::new(&db).expect("defaults should be valid");
        assert_eq!(config.http.http_server_bind_port, 8080);
        assert_eq!(config.network.ingress_ifname, "eth0");
        assert_eq!(config.network.egress_ifname, "eth1");
        assert_eq!(config.network.combined_queue_count, 1);
        assert_eq!(config.network.frame_size, 4096);
    }

    #[test]
    fn db_overrides_interface_names() {
        let db = test_db();
        db.set_setting("ingress_interface", "ens33").unwrap();
        db.set_setting("egress_interface", "ens34").unwrap();
        let config = AppConfig::new(&db).unwrap();
        assert_eq!(config.network.ingress_ifname, "ens33");
        assert_eq!(config.network.egress_ifname, "ens34");
    }

    #[test]
    fn db_overrides_http_port() {
        let db = test_db();
        db.set_setting("http_port", "9090").unwrap();
        let config = AppConfig::new(&db).unwrap();
        assert_eq!(config.http.http_server_bind_port, 9090);
    }

    #[test]
    fn db_overrides_xdp_tuning() {
        let db = test_db();
        db.set_setting("frame_size", "8192").unwrap();
        db.set_setting("combined_queue_count", "4").unwrap();
        let config = AppConfig::new(&db).unwrap();
        assert_eq!(config.network.frame_size, 8192);
        assert_eq!(config.network.combined_queue_count, 4);
    }

    #[test]
    fn invalid_db_values_ignored() {
        let db = test_db();
        db.set_setting("http_port", "not_a_number").unwrap();
        let config = AppConfig::new(&db).unwrap();
        // Should keep default since parse fails
        assert_eq!(config.http.http_server_bind_port, 8080);
    }

    #[test]
    fn empty_db_uses_all_defaults() {
        let db = test_db();
        let config = AppConfig::new(&db).unwrap();
        assert_eq!(config.inference.inference_interval_secs, 5);
        assert_eq!(config.inference.inference_batch_size, 200);
        assert_eq!(config.misc.database_path, "net-guardia.db");
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
        // Default is false (ML inference enabled). Override to true enables CSV logging only.
        let db = test_db();
        db.set_setting("traffic_logging_mode", "true").unwrap();
        let config = AppConfig::new(&db).unwrap();
        assert!(config.inference.traffic_logging_mode);
    }

    #[test]
    fn default_traffic_logging_mode_is_false() {
        // ML inference should be enabled by default, not CSV logging
        let db = test_db();
        let config = AppConfig::new(&db).unwrap();
        assert!(!config.inference.traffic_logging_mode);
    }

    #[test]
    fn db_overrides_pipeline() {
        let db = test_db();
        db.set_setting("pipeline_ingress", "access_control,service").unwrap();
        let config = AppConfig::new(&db).unwrap();
        assert_eq!(config.pipeline.ingress, vec!["access_control", "service"]);
    }
}
