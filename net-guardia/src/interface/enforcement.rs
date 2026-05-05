use async_trait::async_trait;

use crate::domain::common::error::Error;

/// Data Plane BC — rate-limit, DNS blacklist, geo-block aggregate repository.
///
/// These tables back three distinct eBPF map populations but share the
/// lifecycle of "data-plane policy that is not per-IP ACL". Kept disjoint from
/// `AclRepo` so the per-packet matching rules evolve independently from the
/// aggregate policy knobs.
#[async_trait]
pub trait EnforcementRepo: Send + Sync {
    // --- Rate Limit ---
    async fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error>;

    // --- DNS ---
    async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error>;
    async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error>;

    // --- Geo ---
    async fn insert_geo_country(&self, code: &str) -> Result<(), Error>;
    async fn delete_geo_country(&self, code: &str) -> Result<(), Error>;
}
