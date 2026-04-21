use super::helpers::{override_string_nonempty, seed_key};
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

#[derive(Debug, Clone)]
pub struct AclConfig {
    pub geoip_db_name: String,
}

impl AclConfig {
    pub fn defaults() -> Self {
        Self {
            geoip_db_name: "net-guardia/static/geo/dbip-city-lite.mmdb".to_string(),
        }
    }

    pub fn from_settings(repo: &dyn SettingRepo) -> Result<Self, Error> {
        let mut config = Self::defaults();
        override_string_nonempty(&mut config.geoip_db_name, repo, "geoip_db_name")?;
        Ok(config)
    }

    pub fn seed_defaults(repo: &dyn SettingRepo) -> Result<(), Error> {
        seed_key(repo, "geoip_db_name", "net-guardia/static/geo/dbip-city-lite.mmdb")?;
        Ok(())
    }
}
