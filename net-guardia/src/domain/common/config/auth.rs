use super::helpers::{override_parsed, seed_key};
use crate::domain::common::error::Error;
use crate::interface::port::setting::SettingRepo;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_expiry_hours: u64,
}

impl AuthConfig {
    pub fn defaults() -> Self {
        Self { jwt_expiry_hours: 24 }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.jwt_expiry_hours, repo, "jwt_expiry_hours")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "jwt_expiry_hours", "24")?;
        Ok(())
    }
}
