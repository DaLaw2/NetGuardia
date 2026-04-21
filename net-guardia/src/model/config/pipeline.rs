use super::helpers::{override_csv, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
}

impl PipelineConfig {
    pub fn defaults() -> Self {
        Self {
            ingress: vec![
                "access_control".to_string(),
                "rate_limit".to_string(),
                "service".to_string(),
            ],
            egress: Vec::new(),
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_csv(&mut cfg.ingress, repo, "pipeline_ingress")?;
        override_csv(&mut cfg.egress, repo, "pipeline_egress")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "pipeline_ingress", "access_control,rate_limit,service")?;
        seed_key(repo, "pipeline_egress", "")?;
        Ok(())
    }
}
