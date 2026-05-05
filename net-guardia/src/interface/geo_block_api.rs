use crate::domain::common::error::Error;

pub trait GeoBlockPort: Send + Sync {
    fn list_blocked(&self) -> Vec<String>;

    fn block_countries(&self, codes: &[String]) -> Result<u64, Error>;

    fn unblock_countries(&self, codes: &[String]) -> Result<u64, Error>;
}
