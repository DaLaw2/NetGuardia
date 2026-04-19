use crate::model::error::Error;

/// Data-plane geo-block admin port — block / unblock / list country codes.
/// Used by `AclService` for the `/api/acl/geo` HTTP routes.
pub trait GeoBlockPort: Send + Sync {
    /// Add every ISO-3166-1 alpha-2 code in `codes` to the block set.
    /// Returns the number of /24 ranges actually added (existing codes
    /// count as zero).
    fn block_countries(&self, codes: &[String]) -> Result<u64, Error>;

    /// Remove every code in `codes` from the block set. Returns the number
    /// of /24 ranges actually removed.
    fn unblock_countries(&self, codes: &[String]) -> Result<u64, Error>;

    fn list_blocked(&self) -> Vec<String>;
}
