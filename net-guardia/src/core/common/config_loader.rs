use std::collections::HashMap;

use crate::common::error::Error;
use crate::domain::common::config::AppConfig;
use crate::interface::system::config_repo::ConfigRepo;

pub async fn load_app_config(repo: &dyn ConfigRepo) -> Result<AppConfig, Error> {
    let mut values = HashMap::new();
    for (key, _) in AppConfig::default_settings() {
        if let Some(value) = repo.get_config_value(key).await? {
            values.insert(key.to_string(), value);
        }
    }
    AppConfig::from_config_values(&values)
}

pub async fn seed_config_defaults(repo: &dyn ConfigRepo) -> Result<(), Error> {
    for (key, value) in AppConfig::default_settings() {
        if repo.get_config_value(key).await?.is_none() {
            repo.set_config_value(key, &value).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    async fn test_db() -> Database {
        Database::new(":memory:").await.expect("in-memory DB")
    }

    #[tokio::test]
    async fn empty_db_uses_all_defaults() {
        let db = test_db().await;

        let cfg = load_app_config(&db).await.expect("load config");

        assert_eq!(cfg.ml.inference.inference_interval_secs, 5);
        assert_eq!(cfg.ml.inference.inference_batch_size, 200);
        assert_eq!(cfg.system.database_path, "net-guardia.db");
    }

    #[tokio::test]
    async fn db_overrides_runtime_values() {
        let db = test_db().await;
        db.set_config_value("ingress_interface", "ens33").await.unwrap();
        db.set_config_value("egress_interface", "ens34").await.unwrap();
        db.set_config_value("http_port", "9090").await.unwrap();
        db.set_config_value("traffic_logging_mode", "true").await.unwrap();
        db.set_config_value("pipeline_ingress", "access_control,service")
            .await
            .unwrap();
        db.set_config_value("soar_execution_list_limit", "42").await.unwrap();
        db.set_config_value("geoip_cache_capacity", "2048").await.unwrap();

        let cfg = load_app_config(&db).await.expect("load config");

        assert_eq!(cfg.ebpf.ingress_ifname, "ens33");
        assert_eq!(cfg.ebpf.egress_ifname, "ens34");
        assert_eq!(cfg.http_server.port, 9090);
        assert!(cfg.ml.inference.traffic_logging_mode);
        assert_eq!(cfg.pipeline.ingress, vec!["access_control", "service"]);
        assert_eq!(cfg.soar.execution_list_limit, 42);
        assert_eq!(cfg.acl.geoip_cache_capacity, 2048);
    }

    #[tokio::test]
    async fn invalid_db_values_are_ignored() {
        let db = test_db().await;
        db.set_config_value("http_port", "not_a_number").await.unwrap();

        let cfg = load_app_config(&db).await.expect("load config");

        assert_eq!(cfg.http_server.port, 8080);
    }

    #[tokio::test]
    async fn seed_config_defaults_populates_empty_db() {
        let db = test_db().await;

        seed_config_defaults(&db).await.expect("seed config defaults");

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
            db.get_config_value("geoip_cache_capacity").await.unwrap(),
            Some("10000".to_string())
        );
    }

    #[tokio::test]
    async fn seed_config_defaults_does_not_overwrite_existing() {
        let db = test_db().await;
        db.set_config_value("http_port", "9090").await.unwrap();

        seed_config_defaults(&db).await.expect("seed config defaults");

        assert_eq!(
            db.get_config_value("http_port").await.unwrap(),
            Some("9090".to_string())
        );
    }
}
