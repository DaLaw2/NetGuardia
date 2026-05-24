use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "dns")]
#[derive(Debug, Clone)]
pub struct DnsFilterConfig {
    #[setting(key = "dns_max_domains_per_request", default = "1000")]
    pub max_domains_per_request: usize,
}

impl DnsFilterConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.max_domains_per_request > 0, "dns.max_domains_per_request")
    }
}

#[cfg(test)]
mod tests {
    use super::DnsFilterConfig;

    #[test]
    fn zero_request_limit_is_invalid() {
        let mut cfg = DnsFilterConfig::defaults();
        cfg.max_domains_per_request = 0;

        assert!(cfg.validate().is_err());
    }
}
