use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "misc")]
#[derive(Debug, Clone)]
pub struct AclConfig {
    #[setting(key = "geoip_db_path", default = "net-guardia/static/geo/dbip-city-lite.mmdb")]
    pub geoip_db_path: String,
    #[setting(key = "geoip_cache_capacity", default = "10000")]
    pub geoip_cache_capacity: usize,
}

impl AclConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.geoip_cache_capacity > 0, "acl.geoip_cache_capacity")
    }
}
