use super::helpers::{override_string_nonempty, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct SystemConfig {
    pub database_path: String,
    pub report_dir: String,
    pub log_dir: String,
}

impl SystemConfig {
    pub fn defaults() -> Self {
        Self {
            database_path: "net-guardia.db".to_string(),
            report_dir: "/var/lib/netguardia/reports".to_string(),
            log_dir: "logs".to_string(),
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_string_nonempty(&mut cfg.database_path, repo, "database_path")?;
        override_string_nonempty(&mut cfg.report_dir, repo, "report_dir")?;
        override_string_nonempty(&mut cfg.log_dir, repo, "log_dir")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "report_dir", "/var/lib/netguardia/reports")?;
        seed_key(repo, "log_dir", "logs")?;
        Ok(())
    }
}
