use async_trait::async_trait;

use crate::domain::common::error::Error;

/// Data Plane BC — ACL aggregate repository.
///
/// Owns ACL rules (user-managed block/allow lists) and the admin whitelist that
/// SOAR must not block. Kept disjoint from `EnforcementRepo` (rate-limit / DNS /
/// geo) so policy tables can evolve independently of packet-matching tables.
#[async_trait]
pub trait AclRepo: Send + Sync {
    async fn insert_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;

    async fn delete_acl_rule(
        &self,
        ip_version: u8,
        direction: &str,
        list_type: &str,
        ip_address: &str,
        port: u16,
    ) -> Result<(), Error>;

    /// Returns true if a manual (non-SOAR) ACL rule exists for this IP.
    /// Used by the TTL scheduler to avoid removing an eBPF block that the user
    /// explicitly installed.
    async fn has_manual_acl_rule(&self, ip_address: &str) -> Result<bool, Error>;

    async fn list_admin_whitelist(&self) -> Result<Vec<String>, Error>;
    async fn insert_admin_whitelist(&self, ip: &str) -> Result<(), Error>;
    async fn delete_admin_whitelist(&self, ip: &str) -> Result<(), Error>;
}
