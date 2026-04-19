use crate::model::error::Error;

/// Data Plane BC — rate-limit, DNS blacklist, geo-block aggregate repository.
///
/// These tables back three distinct eBPF map populations but share the
/// lifecycle of "data-plane policy that is not per-IP ACL". Kept disjoint from
/// `AclRepo` so the per-packet matching rules evolve independently from the
/// aggregate policy knobs.
pub trait EnforcementRepo: Send + Sync {
    // --- Rate Limit ---
    fn set_rate_limit(&self, key: &str, value: u64) -> Result<(), Error>;

    // --- DNS ---
    fn insert_dns_domain(&self, domain: &str) -> Result<(), Error>;
    fn delete_dns_domain(&self, domain: &str) -> Result<(), Error>;

    // --- Geo ---
    fn insert_geo_country(&self, code: &str) -> Result<(), Error>;
    fn delete_geo_country(&self, code: &str) -> Result<(), Error>;
}
