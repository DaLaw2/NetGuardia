use macros::config_settings;

use crate::common::error::Error;
use crate::common::error::system::SystemError;

pub const VALID_PIPELINE_STAGES: &[&str] = &["access_control", "rate_limit", "service"];

#[config_settings(section = "pipeline")]
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    #[setting(key = "pipeline_ingress", default = "access_control,rate_limit,service", api = false)]
    pub ingress: Vec<String>,
    #[setting(key = "pipeline_egress", default = "", api = false)]
    pub egress: Vec<String>,
}

impl PipelineConfig {
    pub fn validate(&self) -> Result<(), Error> {
        validate_stage_list(&self.ingress)?;
        validate_stage_list(&self.egress)
    }
}

pub fn normalize_pipeline_stages(raw: &str) -> Result<Vec<String>, Error> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    raw.split(',')
        .map(|stage| {
            let stage = stage.trim();
            validate_stage(stage)?;
            Ok(stage.to_string())
        })
        .collect()
}

fn validate_stage_list(stages: &[String]) -> Result<(), Error> {
    for stage in stages {
        validate_stage(stage)?;
    }
    Ok(())
}

fn validate_stage(stage: &str) -> Result<(), Error> {
    if !stage.is_empty() && VALID_PIPELINE_STAGES.contains(&stage) {
        return Ok(());
    }

    Err(SystemError::InvalidPipelineStage(
        stage.to_string(),
        VALID_PIPELINE_STAGES.join(", "),
    ))?
}

#[cfg(test)]
mod tests {
    use super::PipelineConfig;

    #[test]
    fn invalid_pipeline_stage_is_rejected() {
        let mut cfg = PipelineConfig::defaults();
        cfg.ingress = vec!["access_control".to_string(), "mirror".to_string()];

        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_pipeline_stage_is_rejected() {
        let mut cfg = PipelineConfig::defaults();
        cfg.ingress = vec!["access_control".to_string(), String::new(), "service".to_string()];

        assert!(cfg.validate().is_err());
    }
}
