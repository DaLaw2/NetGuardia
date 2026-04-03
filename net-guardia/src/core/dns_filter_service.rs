use std::sync::Arc;

use crate::core::ebpf::dns_filter::DnsFilter;
use crate::interface::port::repository::RepositoryPort;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;

/// Domain service that coordinates DNS filter changes between DB and in-memory service.
/// Write order: eBPF/in-memory first, then DB — if eBPF fails, DB remains clean.
pub struct DnsFilterService {
    db: Arc<dyn RepositoryPort>,
    dns_filter: Arc<DnsFilter>,
}

impl DnsFilterService {
    pub fn new(db: Arc<dyn RepositoryPort>, dns_filter: Arc<DnsFilter>) -> Self {
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
            return Err(MiscError::ValidationError {
                message: format!("too many domains (max {})", max_domains),
            }
            .into());
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
