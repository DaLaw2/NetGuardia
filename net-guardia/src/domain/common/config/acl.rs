use macros::config_settings;

#[config_settings(section = "misc")]
#[derive(Debug, Clone)]
pub struct AclConfig {
    #[setting(key = "geoip_db_path", default = "net-guardia/static/geo/dbip-city-lite.mmdb")]
    pub geoip_db_path: String,
    #[setting(key = "geoip_cache_capacity", default = "10000")]
    pub geoip_cache_capacity: usize,
}
