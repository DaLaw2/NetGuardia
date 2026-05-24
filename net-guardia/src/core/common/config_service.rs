use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;

use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::core::common::config_loader::load_app_config;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::pipeline::normalize_pipeline_stages;
use crate::domain::common::config::section::ConfigSection;
use crate::interface::system::config_repo::ConfigRepo;
use crate::interface::system::secret_store::SecretStorePort;

const SECRET_KEYS: &[&str] = &["smtp_password"];
const CLEARABLE_CONFIG_KEYS: &[&str] = &["smtp_host", "smtp_username", "smtp_sender", "smtp_recipient"];

pub struct ConfigService {
    db: Arc<dyn ConfigRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    app_config: Arc<ArcSwap<AppConfig>>,
}

struct CandidateConfigRepo {
    base: Arc<dyn ConfigRepo>,
    values: HashMap<String, String>,
}

#[async_trait]
impl ConfigRepo for CandidateConfigRepo {
    async fn get_config_value(&self, key: &str) -> Result<Option<String>, Error> {
        if let Some(value) = self.values.get(key) {
            return Ok(Some(value.clone()));
        }
        self.base.get_config_value(key).await
    }

    async fn set_config_value(&self, key: &str, value: &str) -> Result<(), Error> {
        self.base.set_config_value(key, value).await
    }

    async fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error> {
        self.base.get_app_secret(key).await
    }

    async fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        self.base.set_app_secret(key, plaintext).await
    }

    async fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error> {
        self.base.get_notification_config(channel).await
    }

    async fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error> {
        self.base.set_notification_config(channel, config_json).await
    }

    async fn update_config_values_atomically(
        &self,
        config_values: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
    ) -> Result<(), Error> {
        self.base.update_config_values_atomically(config_values, secrets).await
    }
}

impl ConfigService {
    pub fn new(db: Arc<dyn ConfigRepo>, app_config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self {
            db,
            secrets: None,
            app_config,
        }
    }

    pub fn with_secret_store(mut self, secrets: Arc<dyn SecretStorePort>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    pub async fn get_config(&self) -> serde_json::Value {
        let cfg = self.app_config.load();
        let values = cfg.api_setting_values();
        let mut root = serde_json::Map::new();
        for section in ConfigSection::ALL {
            let mut section_obj = serde_json::Map::new();
            section.for_each_key(|key| {
                let value = values.get(key).cloned().unwrap_or_default();
                section_obj.insert(key.to_string(), serde_json::json!(value));
            });
            root.insert(section.name().to_string(), section_obj.into());
        }
        root.insert(
            "pipeline".to_string(),
            serde_json::json!({
                "ingress": cfg.pipeline.ingress.join(","),
                "egress": cfg.pipeline.egress.join(","),
            }),
        );
        root.into()
    }

    pub async fn update_config(&self, body: &serde_json::Value) -> Result<Vec<String>, Error> {
        let mut updated: Vec<String> = Vec::new();
        let mut config_values = Vec::new();
        let mut secrets_to_save = Vec::new();

        for section in ConfigSection::ALL {
            if let Some(section_obj) = body.get(section.name()).and_then(|v| v.as_object()) {
                section.for_each_key(|key| {
                    if let Some(val) = section_obj.get(key).and_then(|v| config_json_value_as_string(key, v)) {
                        config_values.push((key.to_string(), val));
                        updated.push(key.to_string());
                    }
                });
            }
        }

        if let Some(ref secrets) = self.secrets {
            for key in SECRET_KEYS {
                let section = key.split('_').next().unwrap_or("");
                if let Some(val) = body
                    .get(section)
                    .and_then(|v| v.as_object())
                    .and_then(|obj| obj.get(*key))
                    .and_then(json_value_as_string)
                {
                    let envelope = secrets.encrypt_envelope(&val)?;
                    secrets_to_save.push((key.to_string(), envelope));
                    config_values.push((key.to_string(), String::new()));
                    updated.push(key.to_string());
                }
            }
        }

        if let Some(pipeline_obj) = body.get("pipeline").and_then(|v| v.as_object()) {
            for (field, db_key) in [("ingress", "pipeline_ingress"), ("egress", "pipeline_egress")] {
                if let Some(val) = pipeline_obj.get(field).and_then(|v| v.as_str()) {
                    let stages = normalize_pipeline_stages(val)?;
                    config_values.push((db_key.to_string(), stages.join(",")));
                    updated.push(db_key.to_string());
                }
            }
        }

        let candidate_repo = CandidateConfigRepo {
            base: self.db.clone(),
            values: config_values.iter().cloned().collect(),
        };
        let new_cfg = load_app_config(&candidate_repo).await?;
        reject_unapplied_config_values(&config_values, &new_cfg)?;

        self.db
            .update_config_values_atomically(config_values, secrets_to_save)
            .await?;
        self.app_config.store(Arc::new(new_cfg));

        Ok(updated)
    }
}

fn json_value_as_string(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str()
        && !s.is_empty()
    {
        return Some(s.to_string());
    }
    if let Some(b) = v.as_bool() {
        return Some(b.to_string());
    }
    v.as_number().map(ToString::to_string)
}

fn config_json_value_as_string(key: &str, v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        if CLEARABLE_CONFIG_KEYS.contains(&key) {
            return Some(s.trim().to_string());
        }
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    if let Some(b) = v.as_bool() {
        return Some(b.to_string());
    }
    v.as_number().map(ToString::to_string)
}

fn reject_unapplied_config_values(config_values: &[(String, String)], new_cfg: &AppConfig) -> Result<(), Error> {
    let applied_values = new_cfg.api_setting_values();
    for (key, value) in config_values {
        if SECRET_KEYS.contains(&key.as_str()) || matches!(key.as_str(), "pipeline_ingress" | "pipeline_egress") {
            continue;
        }
        let Some(applied) = applied_values.get(key.as_str()) else {
            continue;
        };
        if applied != value {
            Err(SystemError::InvalidConfigField(key.clone()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    #[tokio::test]
    async fn invalid_config_update_is_not_persisted() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config);

        let body = serde_json::json!({
            "http": {
                "http_port": 0
            }
        });

        assert!(service.update_config(&body).await.is_err());
        assert_eq!(db.get_config_value("http_port").await.unwrap(), None);
    }

    #[tokio::test]
    async fn unparsable_config_update_is_not_persisted() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config);

        let body = serde_json::json!({
            "http": {
                "http_port": "not_a_number"
            }
        });

        assert!(service.update_config(&body).await.is_err());
        assert_eq!(db.get_config_value("http_port").await.unwrap(), None);
    }

    #[tokio::test]
    async fn pipeline_update_is_normalized_before_persisting() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config.clone());

        let body = serde_json::json!({
            "pipeline": {
                "ingress": " access_control , service ",
                "egress": "   "
            }
        });

        service.update_config(&body).await.expect("pipeline update");

        assert_eq!(
            db.get_config_value("pipeline_ingress").await.unwrap(),
            Some("access_control,service".to_string())
        );
        assert_eq!(
            db.get_config_value("pipeline_egress").await.unwrap(),
            Some(String::new())
        );
        assert_eq!(app_config.load().pipeline.ingress, vec!["access_control", "service"]);
        assert!(app_config.load().pipeline.egress.is_empty());
    }

    #[tokio::test]
    async fn invalid_pipeline_update_is_not_persisted() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config);

        let body = serde_json::json!({
            "pipeline": {
                "ingress": "access_control,,service"
            }
        });

        assert!(service.update_config(&body).await.is_err());
        assert_eq!(db.get_config_value("pipeline_ingress").await.unwrap(), None);
    }

    #[tokio::test]
    async fn update_config_allows_clearing_smtp_recipient() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        db.set_config_value("smtp_recipient", "ops@example.test")
            .await
            .expect("seed smtp recipient");
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config.clone());

        let body = serde_json::json!({
            "smtp": {
                "smtp_recipient": ""
            }
        });

        let updated = service.update_config(&body).await.expect("clear smtp recipient");

        assert_eq!(updated, vec!["smtp_recipient".to_string()]);
        assert_eq!(
            db.get_config_value("smtp_recipient").await.unwrap(),
            Some(String::new())
        );
        assert_eq!(app_config.load().notification.smtp.recipient, "");
    }

    #[tokio::test]
    async fn update_config_trims_clearable_smtp_text_fields() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            load_app_config(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn ConfigRepo>, app_config.clone());

        let body = serde_json::json!({
            "smtp": {
                "smtp_host": " smtp.example.test ",
                "smtp_username": " mailer ",
                "smtp_sender": " sender@example.test ",
                "smtp_recipient": " security@example.test "
            }
        });

        let updated = service.update_config(&body).await.expect("update smtp config");

        assert_eq!(
            updated,
            vec![
                "smtp_host".to_string(),
                "smtp_username".to_string(),
                "smtp_sender".to_string(),
                "smtp_recipient".to_string()
            ]
        );
        assert_eq!(
            db.get_config_value("smtp_host").await.unwrap(),
            Some("smtp.example.test".to_string())
        );
        assert_eq!(
            db.get_config_value("smtp_username").await.unwrap(),
            Some("mailer".to_string())
        );
        assert_eq!(
            db.get_config_value("smtp_sender").await.unwrap(),
            Some("sender@example.test".to_string())
        );
        assert_eq!(
            db.get_config_value("smtp_recipient").await.unwrap(),
            Some("security@example.test".to_string())
        );
        assert_eq!(app_config.load().notification.smtp.host, "smtp.example.test");
        assert_eq!(app_config.load().notification.smtp.username, "mailer");
        assert_eq!(app_config.load().notification.smtp.sender, "sender@example.test");
        assert_eq!(app_config.load().notification.smtp.recipient, "security@example.test");
    }
}
