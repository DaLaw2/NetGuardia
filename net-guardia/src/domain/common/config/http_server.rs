use super::helpers::{override_bool, override_csv, override_parsed, seed_key};
use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

#[derive(Debug, Clone)]
pub struct HttpServerConfig {
    pub port: u16,
    pub cors_allowed_origins: Vec<String>,
    pub force_https: bool,
}

impl HttpServerConfig {
    pub fn defaults() -> Self {
        Self {
            port: 8080,
            cors_allowed_origins: Vec::new(),
            force_https: false,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.port, repo, "http_port")?;
        override_csv(&mut cfg.cors_allowed_origins, repo, "cors_allowed_origins")?;
        override_bool(&mut cfg.force_https, repo, "force_https")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "http_port", "8080")?;
        seed_key(repo, "cors_allowed_origins", "")?;
        seed_key(repo, "force_https", "false")?;
        Ok(())
    }
}
