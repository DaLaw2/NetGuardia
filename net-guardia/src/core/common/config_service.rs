use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;

use crate::domain::common::config::AppConfig;
use crate::domain::common::config::section::ConfigSection;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::app_repo::AppRepo;
use crate::interface::config_repo::ConfigRepo;
use crate::interface::secret_store::SecretStorePort;

const SECRET_KEYS: &[&str] = &["smtp_password"];

const VALID_PIPELINE_STAGES: &[&str] = &["access_control", "rate_limit", "service"];

pub struct ConfigService {
    db: Arc<dyn AppRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    app_config: Arc<ArcSwap<AppConfig>>,
}

struct CandidateConfigRepo {
    base: Arc<dyn AppRepo>,
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
    pub fn new(db: Arc<dyn AppRepo>, app_config: Arc<ArcSwap<AppConfig>>) -> Self {
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
            for key in section.keys() {
                let value = values.get(key).cloned().unwrap_or_default();
                section_obj.insert(key.to_string(), serde_json::Value::String(value));
            }
            root.insert(section.name().to_string(), serde_json::Value::Object(section_obj));
        }
        root.insert(
            "pipeline".to_string(),
            serde_json::json!({
                "ingress": cfg.pipeline.ingress.join(","),
                "egress": cfg.pipeline.egress.join(","),
            }),
        );
        serde_json::Value::Object(root)
    }

    pub async fn update_config(&self, body: &serde_json::Value) -> Result<Vec<String>, Error> {
        let mut updated: Vec<String> = Vec::new();
        let mut config_values = Vec::new();
        let mut secrets_to_save = Vec::new();

        for section in ConfigSection::ALL {
            if let Some(section_obj) = body.get(section.name()).and_then(|v| v.as_object()) {
                for key in section.keys() {
                    if let Some(val) = section_obj.get(*key).and_then(json_value_as_string) {
                        config_values.push((key.to_string(), val));
                        updated.push(key.to_string());
                    }
                }
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
                    if !val.is_empty() {
                        let stages: Vec<&str> = val.split(',').map(|s| s.trim()).collect();
                        for stage in &stages {
                            if !stage.is_empty() && !VALID_PIPELINE_STAGES.contains(stage) {
                                Err(MiscError::ValidationError(format!(
                                    "Invalid pipeline stage '{}'. Valid stages: {}",
                                    stage,
                                    VALID_PIPELINE_STAGES.join(", ")
                                )))?;
                            }
                        }
                    }
                    config_values.push((db_key.to_string(), val.to_string()));
                    updated.push(db_key.to_string());
                }
            }
        }

        let candidate_repo = CandidateConfigRepo {
            base: self.db.clone(),
            values: config_values.iter().cloned().collect(),
        };
        let new_cfg = AppConfig::from_config_repo(&candidate_repo).await?;

        self.db
            .update_config_values_atomically(config_values, secrets_to_save)
            .await?;
        self.app_config.store(Arc::new(new_cfg));

        Ok(updated)
    }
}

fn json_value_as_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    #[tokio::test]
    async fn invalid_config_update_is_not_persisted() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let app_config = Arc::new(ArcSwap::from_pointee(
            AppConfig::from_config_repo(db.as_ref()).await.expect("initial config"),
        ));
        let service = ConfigService::new(db.clone() as Arc<dyn AppRepo>, app_config);

        let body = serde_json::json!({
            "http": {
                "http_port": 0
            }
        });

        assert!(service.update_config(&body).await.is_err());
        assert_eq!(db.get_config_value("http_port").await.unwrap(), None);
    }
}
