use super::helpers::{override_parsed, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct DnsFilterConfig {
    pub max_domains_per_request: usize,
}

impl DnsFilterConfig {
    pub fn defaults() -> Self {
        Self {
            max_domains_per_request: 1000,
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut cfg = Self::defaults();
        override_parsed(&mut cfg.max_domains_per_request, repo, "dns_max_domains_per_request")?;
        Ok(cfg)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "dns_max_domains_per_request", "1000")?;
        Ok(())
    }
}
