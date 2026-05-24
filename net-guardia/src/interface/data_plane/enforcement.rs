use async_trait::async_trait;

use crate::common::error::Error;

#[async_trait]
pub trait RateLimitWritePort: Send + Sync {
    async fn load_rate_limit_config(&self) -> Result<Vec<(String, u64)>, Error>;
    async fn set_rate_limits(&self, values: &[(String, u64)]) -> Result<(), Error>;
}

#[async_trait]
pub trait DnsEnforcementPort: Send + Sync {
    async fn load_dns_domains(&self) -> Result<Vec<String>, Error>;
    async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error>;
    async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error>;
}

#[async_trait]
pub trait GeoEnforcementPort: Send + Sync {
    async fn load_geo_countries(&self) -> Result<Vec<String>, Error>;
    async fn insert_geo_countries(&self, codes: &[String]) -> Result<(), Error>;
    async fn delete_geo_countries(&self, codes: &[String]) -> Result<(), Error>;
}
