use std::sync::Arc;

use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::dns_filter_api::DnsFilterPort;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;

/// Domain service that coordinates DNS filter changes between DB and in-memory service.
/// Write order: eBPF/in-memory first, then DB — if eBPF fails, DB remains clean.
pub struct DnsFilterService {
    db: Arc<dyn AppRepo>,
    dns_filter: Arc<dyn DnsFilterPort>,
}

impl DnsFilterService {
    pub fn new(db: Arc<dyn AppRepo>, dns_filter: Arc<dyn DnsFilterPort>) -> Self {
        Self { db, dns_filter }
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.dns_filter.list_domains()
    }

    pub fn add_domains(&self, domains: &[String]) -> Result<usize, Error> {
        let max_domains: usize = self
            .db
            .get_setting("dns_max_domains_per_request")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);
        if domains.len() > max_domains {
            Err(MiscError::ValidationError(format!(
                "too many domains (max {})",
                max_domains
            )))?;
        }
        // eBPF first
        for domain in domains {
            self.dns_filter.add_domain(domain)?;
        }
        // Then DB
        for domain in domains {
            self.db.insert_dns_domain(domain)?;
        }
        Ok(domains.len())
    }

    pub fn remove_domains(&self, domains: &[String]) -> Result<usize, Error> {
        // eBPF first
        for domain in domains {
            self.dns_filter.remove_domain(domain)?;
        }
        // Then DB
        for domain in domains {
            self.db.delete_dns_domain(domain)?;
        }
        Ok(domains.len())
    }
}
