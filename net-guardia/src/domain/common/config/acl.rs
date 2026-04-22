use macros::config_settings;

#[config_settings(section = "misc")]
#[derive(Debug, Clone)]
pub struct AclConfig {
    #[setting(key = "geoip_db_name", default = "net-guardia/static/geo/dbip-city-lite.mmdb")]
    pub geoip_db_name: String,
}
