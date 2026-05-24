use crate::common::error::Error;

pub trait DnsFilterPort: Send + Sync {
    fn list_domains(&self) -> Vec<String>;
    fn validate_domain(&self, domain: &str) -> Result<(), Error>;
    fn add_domain(&self, domain: &str) -> Result<(), Error>;
    fn remove_domain(&self, domain: &str) -> Result<(), Error>;
}
