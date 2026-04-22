use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::dns_filter_api::DnsFilterPort;

/// Domain service that coordinates DNS filter changes between DB and in-memory service.
/// Write order: eBPF/in-memory first, then DB — if eBPF fails, DB remains clean.
pub struct DnsFilterService {
    db: Arc<dyn AppRepo>,
    dns_filter: Arc<dyn DnsFilterPort>,
    config: Arc<ArcSwap<AppConfig>>,
}

impl DnsFilterService {
    pub fn new(db: Arc<dyn AppRepo>, dns_filter: Arc<dyn DnsFilterPort>, config: Arc<ArcSwap<AppConfig>>) -> Self {
        Self { db, dns_filter, config }
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.dns_filter.list_domains()
    }

    pub fn add_domains(&self, domains: &[String]) -> Result<usize, Error> {
        let max_domains = self.config.load().dns_filter.max_domains_per_request;
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
