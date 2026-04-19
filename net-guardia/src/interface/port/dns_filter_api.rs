use crate::model::error::Error;

/// Admin-level DNS filter port — add/remove/list domains on the blacklist.
/// Used by `DnsFilterService` (HTTP-driven CRUD). Kept separate from
/// `DnsQueryFilter` (which is the fast-path check) to reflect their distinct
/// call sites and latency profiles.
pub trait DnsFilterPort: Send + Sync {
    fn add_domain(&self, domain: &str) -> Result<(), Error>;
    fn remove_domain(&self, domain: &str) -> Result<(), Error>;
    fn list_domains(&self) -> Vec<String>;
}
