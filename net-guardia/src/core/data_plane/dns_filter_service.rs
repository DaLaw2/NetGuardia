use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::dns_filter_api::DnsFilterPort;
use crate::interface::enforcement::EnforcementRepo;

/// Domain service that coordinates DNS filter changes between DB and in-memory service.
/// Domains are validated up front, runtime state is changed first, and DB batch
/// failure rolls runtime back so persisted and live policy do not drift.
pub struct DnsFilterService {
    db: Arc<dyn EnforcementRepo>,
    dns_filter: Arc<dyn DnsFilterPort>,
    config: Arc<ArcSwap<AppConfig>>,
}

impl DnsFilterService {
    pub fn new(
        db: Arc<dyn EnforcementRepo>,
        dns_filter: Arc<dyn DnsFilterPort>,
        config: Arc<ArcSwap<AppConfig>>,
    ) -> Self {
        Self { db, dns_filter, config }
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.dns_filter.list_domains()
    }

    pub async fn add_domains(&self, domains: &[String]) -> Result<usize, Error> {
        let max_domains = self.config.load().dns_filter.max_domains_per_request;
        if domains.len() > max_domains {
            Err(MiscError::ValidationError(format!(
                "too many domains (max {})",
                max_domains
            )))?;
        }
        self.validate_domains(domains)?;
        let mut applied: Vec<&String> = Vec::new();
        for domain in domains {
            if let Err(err) = self.dns_filter.add_domain(domain) {
                self.rollback_added(&applied);
                return Err(err);
            }
            applied.push(domain);
        }
        if let Err(err) = self.db.insert_dns_domains(domains).await {
            self.rollback_added(&applied);
            return Err(err);
        }
        Ok(domains.len())
    }

    pub async fn remove_domains(&self, domains: &[String]) -> Result<usize, Error> {
        self.validate_domains(domains)?;
        let mut applied: Vec<&String> = Vec::new();
        for domain in domains {
            if let Err(err) = self.dns_filter.remove_domain(domain) {
                self.rollback_removed(&applied);
                return Err(err);
            }
            applied.push(domain);
        }
        if let Err(err) = self.db.delete_dns_domains(domains).await {
            self.rollback_removed(&applied);
            return Err(err);
        }
        Ok(domains.len())
    }

    fn validate_domains(&self, domains: &[String]) -> Result<(), Error> {
        for domain in domains {
            self.dns_filter.validate_domain(domain)?;
        }
        Ok(())
    }

    fn rollback_added(&self, domains: &[&String]) {
        for domain in domains {
            let _ = self.dns_filter.remove_domain(domain);
        }
    }

    fn rollback_removed(&self, domains: &[&String]) {
        for domain in domains {
            let _ = self.dns_filter.add_domain(domain);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::adapter::persistence::Database;
    use crate::core::data_plane::dns_filter::DnsFilter;

    struct FailingDnsRepo {
        fail_insert: bool,
        fail_delete: bool,
        domains: Mutex<Vec<String>>,
    }

    impl FailingDnsRepo {
        fn new(fail_insert: bool, fail_delete: bool) -> Self {
            Self {
                fail_insert,
                fail_delete,
                domains: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl EnforcementRepo for FailingDnsRepo {
        async fn set_rate_limit(&self, _key: &str, _value: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
            if self.fail_insert {
                Err(MiscError::ValidationError("forced insert failure".to_string()))?;
            }
            self.domains.lock().unwrap().extend_from_slice(domains);
            Ok(())
        }

        async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
            if self.fail_delete {
                Err(MiscError::ValidationError("forced delete failure".to_string()))?;
            }
            self.domains.lock().unwrap().retain(|d| !domains.contains(d));
            Ok(())
        }

        async fn insert_geo_country(&self, _code: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn delete_geo_country(&self, _code: &str) -> Result<(), Error> {
            Ok(())
        }
    }

    async fn test_config() -> Arc<ArcSwap<AppConfig>> {
        let db = Database::new(":memory:").await.expect("test db");
        Arc::new(ArcSwap::from_pointee(
            AppConfig::from_config_repo(&db).await.expect("test config"),
        ))
    }

    #[tokio::test]
    async fn add_domains_rolls_back_runtime_when_db_batch_fails() {
        let filter = Arc::new(DnsFilter::new());
        let service = DnsFilterService::new(
            Arc::new(FailingDnsRepo::new(true, false)),
            filter.clone(),
            test_config().await,
        );

        let result = service.add_domains(&["example.com".to_string()]).await;

        assert!(result.is_err());
        assert!(filter.list_domains().is_empty());
    }

    #[tokio::test]
    async fn remove_domains_restores_runtime_when_db_batch_fails() {
        let filter = Arc::new(DnsFilter::new());
        filter.add_domain("example.com").unwrap();
        let service = DnsFilterService::new(
            Arc::new(FailingDnsRepo::new(false, true)),
            filter.clone(),
            test_config().await,
        );

        let result = service.remove_domains(&["example.com".to_string()]).await;

        assert!(result.is_err());
        assert!(filter.list_domains().contains(&"example.com".to_string()));
    }
}
