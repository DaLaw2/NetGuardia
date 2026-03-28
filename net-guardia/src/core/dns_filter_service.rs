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

const MAX_DNS_DOMAINS_PER_REQUEST: usize = 1000;

impl DnsFilterService {
    pub fn new(db: Arc<dyn RepositoryPort>, dns_filter: Arc<DnsFilter>) -> Self {
        Self { db, dns_filter }
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.dns_filter.list_domains()
    }

    pub fn add_domains(&self, domains: &[String]) -> Result<usize, Error> {
        if domains.len() > MAX_DNS_DOMAINS_PER_REQUEST {
            return Err(MiscError::ValidationError {
                message: format!("too many domains (max {})", MAX_DNS_DOMAINS_PER_REQUEST),
            }.into());
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
