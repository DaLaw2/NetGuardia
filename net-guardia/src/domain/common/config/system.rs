use std::fmt;
use std::str::FromStr;

use crate::common::error::Error;
use crate::domain::common::config::constants::{ENFORCE_MODE_ENFORCE, ENFORCE_MODE_ML_ONLY, ENFORCE_MODE_MONITOR};
use crate::domain::common::config::require_config_field;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EnforceMode {
    Monitor,
    MlOnly,
    Enforce,
}

impl EnforceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monitor => ENFORCE_MODE_MONITOR,
            Self::MlOnly => ENFORCE_MODE_ML_ONLY,
            Self::Enforce => ENFORCE_MODE_ENFORCE,
        }
    }
}

impl fmt::Display for EnforceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EnforceMode {
    type Err = ();

    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            ENFORCE_MODE_MONITOR => Ok(Self::Monitor),
            ENFORCE_MODE_ML_ONLY => Ok(Self::MlOnly),
            ENFORCE_MODE_ENFORCE => Ok(Self::Enforce),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemConfig {
    pub enforce_mode: EnforceMode,
    pub database_path: String,
    pub report_dir: String,
    pub log_dir: String,
}

pub fn is_valid_enforce_mode(mode: &str) -> bool {
    mode.parse::<EnforceMode>().is_ok()
}

impl SystemConfig {
    pub fn defaults() -> Self {
        Self {
            enforce_mode: EnforceMode::Monitor,
            database_path: "net-guardia.db".to_string(),
            report_dir: "/var/lib/netguardia/reports".to_string(),
            log_dir: "logs".to_string(),
        }
    }

    pub fn apply_config_values(&mut self, values: &crate::domain::common::config::ConfigValues) {
        if let Some(mode) = values.get("enforce_mode")
            && let Ok(parsed) = mode.parse::<EnforceMode>()
        {
            self.enforce_mode = parsed;
        }
        if let Some(database_path) = values.get("database_path")
            && !database_path.is_empty()
        {
            self.database_path = database_path.clone();
        }
        if let Some(report_dir) = values.get("report_dir")
            && !report_dir.is_empty()
        {
            self.report_dir = report_dir.clone();
        }
        if let Some(log_dir) = values.get("log_dir")
            && !log_dir.is_empty()
        {
            self.log_dir = log_dir.clone();
        }
    }

    pub fn validate_config_values(values: &crate::domain::common::config::ConfigValues) -> Result<(), Error> {
        if let Some(mode) = values.get("enforce_mode") {
            require_config_field(mode.parse::<EnforceMode>().is_ok(), "system.enforce_mode")?;
        }
        Ok(())
    }

    pub fn default_settings() -> Vec<(&'static str, String)> {
        vec![
            ("enforce_mode", ENFORCE_MODE_MONITOR.to_string()),
            ("database_path", "net-guardia.db".to_string()),
            ("report_dir", "/var/lib/netguardia/reports".to_string()),
            ("log_dir", "logs".to_string()),
        ]
    }

    pub fn api_values(&self) -> Vec<(&'static str, String)> {
        vec![("enforce_mode", self.enforce_mode.to_string())]
    }

    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(is_valid_enforce_mode(self.enforce_mode.as_str()), "system.enforce_mode")
    }
}

#[cfg(test)]
mod tests {
    use super::SystemConfig;

    #[test]
    fn invalid_enforce_mode_is_rejected() {
        let values = [("enforce_mode".to_string(), "unknown".to_string())].into();

        assert!(SystemConfig::validate_config_values(&values).is_err());
    }
}
