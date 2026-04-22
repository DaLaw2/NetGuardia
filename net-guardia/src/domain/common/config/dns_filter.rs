use macros::config_settings;

#[config_settings(section = "dns")]
#[derive(Debug, Clone)]
pub struct DnsFilterConfig {
    #[setting(key = "dns_max_domains_per_request", default = "1000")]
    pub max_domains_per_request: usize,
}
