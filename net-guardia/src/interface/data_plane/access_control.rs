use crate::common::error::Error;

pub trait AccessControlPort: Send + Sync {
    fn block_ip(&self, ip: &str) -> Result<(), Error>;
    fn unblock_ip(&self, ip: &str) -> Result<(), Error>;
}
