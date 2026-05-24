use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use macros::log;

use crate::common::error::Error;
use crate::common::log::data_plane::DataPlaneLog;
use crate::domain::common::config::AppConfig;
use crate::domain::data_plane::error::EbpfError;
use crate::interface::data_plane::dns_filter_api::DnsFilterPort;
use crate::interface::data_plane::enforcement::DnsEnforcementPort;

pub struct DnsFilterService {
    db: Arc<dyn DnsEnforcementPort>,
    dns_filter: Arc<dyn DnsFilterPort>,
    config: Arc<ArcSwap<AppConfig>>,
}

impl DnsFilterService {
    pub fn new(
        db: Arc<dyn DnsEnforcementPort>,
        dns_filter: Arc<dyn DnsFilterPort>,
        config: Arc<ArcSwap<AppConfig>>,
    ) -> Self {
        Self { db, dns_filter, config }
    }

    pub async fn restore(&self) {
        let domains = match self.db.load_dns_domains().await {
            Ok(d) => d,
            Err(_) => return,
        };
        for domain in &domains {
            if let Err(e) = self.dns_filter.add_domain(domain) {
                log!(DataPlaneLog::DnsRestoreFailed(domain.clone(), e.to_string()));
            }
        }
        if !domains.is_empty() {
            log!(DataPlaneLog::DnsBlacklistRestored(domains.len()));
        }
    }

    pub fn list_domains(&self) -> Vec<String> {
        self.dns_filter.list_domains()
    }

    pub async fn add_domains(&self, domains: &[String]) -> Result<usize, Error> {
        self.ensure_request_within_limit(domains)?;
        let domains = self.normalized_domains(domains)?;
        let mut applied: Vec<&String> = Vec::new();
        for domain in &domains {
            if let Err(err) = self.dns_filter.add_domain(domain) {
                self.rollback_added(&applied);
                return Err(err);
            }
            applied.push(domain);
        }
        if let Err(err) = self.db.insert_dns_domains(&domains).await {
            self.rollback_added(&applied);
            return Err(err);
        }
        Ok(domains.len())
    }

    pub async fn remove_domains(&self, domains: &[String]) -> Result<usize, Error> {
        self.ensure_request_within_limit(domains)?;
        let domains = self.normalized_domains(domains)?;
        let mut applied: Vec<&String> = Vec::new();
        for domain in &domains {
            if let Err(err) = self.dns_filter.remove_domain(domain) {
                self.rollback_removed(&applied);
                return Err(err);
            }
            applied.push(domain);
        }
        if let Err(err) = self.db.delete_dns_domains(&domains).await {
            self.rollback_removed(&applied);
            return Err(err);
        }
        Ok(domains.len())
    }

    fn ensure_request_within_limit(&self, domains: &[String]) -> Result<(), Error> {
        let max_domains = self.config.load().dns_filter.max_domains_per_request;
        if domains.len() > max_domains {
            Err(EbpfError::TooManyDnsDomains(max_domains))?;
        }
        Ok(())
    }

    fn normalized_domains(&self, domains: &[String]) -> Result<Vec<String>, Error> {
        let mut seen = HashSet::new();
        let mut normalized = Vec::new();
        for domain in domains {
            let domain = canonical_dns_domain(domain);
            self.dns_filter.validate_domain(&domain)?;
            if seen.insert(domain.clone()) {
                normalized.push(domain);
            }
        }
        Ok(normalized)
    }

    fn rollback_added(&self, domains: &[&String]) {
        for domain in domains {
            if let Err(err) = self.dns_filter.remove_domain(domain) {
                log!(DataPlaneLog::DnsRollbackFailed((*domain).clone(), err.to_string()));
            }
        }
    }

    fn rollback_removed(&self, domains: &[&String]) {
        for domain in domains {
            if let Err(err) = self.dns_filter.add_domain(domain) {
                log!(DataPlaneLog::DnsRollbackFailed((*domain).clone(), err.to_string()));
            }
        }
    }
}

fn canonical_dns_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::adapter::persistence::Database;
    use crate::common::error::database::DatabaseError;
    use crate::core::common::config_loader::load_app_config;
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
    impl DnsEnforcementPort for FailingDnsRepo {
        async fn load_dns_domains(&self) -> Result<Vec<String>, Error> {
            Ok(self.domains.lock().unwrap().clone())
        }

        async fn insert_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
            if self.fail_insert {
                Err(DatabaseError::QueryFailed("forced insert failure"))?;
            }
            self.domains.lock().unwrap().extend_from_slice(domains);
            Ok(())
        }

        async fn delete_dns_domains(&self, domains: &[String]) -> Result<(), Error> {
            if self.fail_delete {
                Err(DatabaseError::QueryFailed("forced delete failure"))?;
            }
            self.domains.lock().unwrap().retain(|d| !domains.contains(d));
            Ok(())
        }
    }

    async fn test_config() -> Arc<ArcSwap<AppConfig>> {
        let db = Database::new(":memory:").await.expect("test db");
        Arc::new(ArcSwap::from_pointee(load_app_config(&db).await.expect("test config")))
    }

    fn test_config_with_domain_limit(max_domains_per_request: usize) -> Arc<ArcSwap<AppConfig>> {
        let mut config = AppConfig::defaults();
        config.dns_filter.max_domains_per_request = max_domains_per_request;
        Arc::new(ArcSwap::from_pointee(config))
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

    #[tokio::test]
    async fn remove_domains_rejects_batches_over_configured_limit() {
        let filter = Arc::new(DnsFilter::new());
        filter.add_domain("example.com").unwrap();
        filter.add_domain("example.net").unwrap();
        let service = DnsFilterService::new(
            Arc::new(FailingDnsRepo::new(false, false)),
            filter.clone(),
            test_config_with_domain_limit(1),
        );

        let result = service
            .remove_domains(&["example.com".to_string(), "example.net".to_string()])
            .await;

        assert!(matches!(
            result,
            Err(Error::Ebpf(EbpfError::TooManyDnsDomains { max: 1 }))
        ));
        assert!(filter.list_domains().contains(&"example.com".to_string()));
        assert!(filter.list_domains().contains(&"example.net".to_string()));
    }

    #[tokio::test]
    async fn add_domains_persists_canonical_domains_once() {
        let repo = Arc::new(FailingDnsRepo::new(false, false));
        let filter = Arc::new(DnsFilter::new());
        let service = DnsFilterService::new(repo.clone(), filter.clone(), test_config().await);

        let count = service
            .add_domains(&[
                " Example.COM. ".to_string(),
                "example.com".to_string(),
                "EXAMPLE.NET".to_string(),
            ])
            .await
            .expect("add domains");

        assert_eq!(count, 2);
        assert!(filter.list_domains().contains(&"example.com".to_string()));
        assert!(filter.list_domains().contains(&"example.net".to_string()));
        assert_eq!(
            *repo.domains.lock().expect("test lock"),
            vec!["example.com".to_string(), "example.net".to_string()]
        );
    }

    #[tokio::test]
    async fn remove_domains_deletes_canonical_persisted_domain() {
        let repo = Arc::new(FailingDnsRepo::new(false, false));
        repo.domains.lock().expect("test lock").push("example.com".to_string());
        let filter = Arc::new(DnsFilter::new());
        filter.add_domain("example.com").unwrap();
        let service = DnsFilterService::new(repo.clone(), filter.clone(), test_config().await);

        let count = service
            .remove_domains(&[" Example.COM. ".to_string(), "example.com".to_string()])
            .await
            .expect("remove domains");

        assert_eq!(count, 1);
        assert!(!filter.list_domains().contains(&"example.com".to_string()));
        assert!(repo.domains.lock().expect("test lock").is_empty());
    }
}
