use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::domain::common::config::AppConfig;
use crate::domain::common::config::section::ConfigSection;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::secret_store::SecretStorePort;

const SECRET_KEYS: &[&str] = &["smtp_password"];

const VALID_PIPELINE_STAGES: &[&str] = &["access_control", "rate_limit", "service"];

pub struct ConfigService {
    db: Arc<dyn AppRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    app_config: Arc<ArcSwap<AppConfig>>,
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

    pub fn get_config(&self) -> serde_json::Value {
        let get = |key: &str| -> String { self.db.get_setting(key).ok().flatten().unwrap_or_default() };

        let mut root = serde_json::Map::new();
        for section in ConfigSection::ALL {
            let mut section_obj = serde_json::Map::new();
            for key in section.keys() {
                section_obj.insert(key.to_string(), serde_json::Value::String(get(key)));
            }
            root.insert(section.name().to_string(), serde_json::Value::Object(section_obj));
        }
        root.insert(
            "pipeline".to_string(),
            serde_json::json!({
                "ingress": get("pipeline_ingress"),
                "egress": get("pipeline_egress"),
            }),
        );
        serde_json::Value::Object(root)
    }

    pub fn update_config(&self, body: &serde_json::Value) -> Result<Vec<String>, Error> {
        let mut updated: Vec<String> = Vec::new();
        let mut new_cfg: Option<AppConfig> = None;

        self.db.transaction(&mut |repo| {
            for section in ConfigSection::ALL {
                if let Some(section_obj) = body.get(section.name()).and_then(|v| v.as_object()) {
                    for key in section.keys() {
                        if let Some(val) = section_obj.get(*key).and_then(json_value_as_string) {
                            repo.set_setting(key, &val)?;
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
                        repo.set_app_secret(key, &envelope)?;
                        repo.set_setting(key, "")?;
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
                        repo.set_setting(db_key, val)?;
                        updated.push(db_key.to_string());
                    }
                }
            }

            new_cfg = Some(AppConfig::from_settings(repo)?);
            Ok(())
        })?;

        if let Some(cfg) = new_cfg {
            self.app_config.store(Arc::new(cfg));
        }

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
