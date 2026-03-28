use async_trait::async_trait;

use crate::model::error::Error;

/// Port for blocking/unblocking IP addresses in the network data plane.
/// Adapters: EbpfAccessControlAdapter (wraps eBPF AccessControl)
#[async_trait]
pub trait AccessControlPort: Send + Sync {
    /// Block an IP address (adds to source blacklist in the data plane).
    /// Accepts both IPv4 ("1.2.3.4") and IPv6 ("::1") strings.
    async fn block_ip(&self, ip: &str) -> Result<(), Error>;

    /// Unblock an IP address (removes from source blacklist in the data plane).
    /// Accepts both IPv4 and IPv6 strings. No-op if IP was not blocked.
    async fn unblock_ip(&self, ip: &str) -> Result<(), Error>;
}
