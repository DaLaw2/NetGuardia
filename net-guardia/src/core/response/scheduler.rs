use std::sync::Arc;

use futures_util::StreamExt;
use futures_util::stream;
use macros::log;
use tokio::task::spawn_blocking;

use crate::common::error::Error;
use crate::common::utils::ip_address::ip_version_from_str;
use crate::core::response::engine::SoarEngine;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::interface::data_plane::access_control::AccessControlPort;
use crate::interface::response::soar::SoarControlRepo;

const TTL_UNBLOCK_CONCURRENCY: usize = 16;

pub struct TtlScheduler {
    db: Arc<dyn SoarControlRepo>,
    access_control: Arc<dyn AccessControlPort>,
    soar_engine: Arc<SoarEngine>,
}

impl TtlScheduler {
    pub fn new(
        db: Arc<dyn SoarControlRepo>,
        access_control: Arc<dyn AccessControlPort>,
        soar_engine: Arc<SoarEngine>,
    ) -> Self {
        Self {
            db,
            access_control,
            soar_engine,
        }
    }

    pub async fn sweep(&self) -> Result<(), Error> {
        if let Err(e) = self.soar_engine.check_rate_limit_restoration().await {
            log!(SoarLog::RateLimitRestorationCheckFailed(e.to_string()));
        }
        self.soar_engine.cleanup_expired_cooldowns();

        let expired = self.db.list_expired_soar_blocks().await?;

        if expired.is_empty() {
            return Ok(());
        }

        let mut removed = 0u32;
        let mut skipped = 0u32;
        let mut committed_unblocks = Vec::new();

        for block in &expired {
            let has_manual_rule = self.db.has_manual_acl_rule(&block.source_ip).await?;

            if has_manual_rule {
                self.db.mark_soar_block_unblocked(block.id).await?;
                self.soar_engine.decrement_block_count();
                skipped += 1;
                log!(SoarLog::WhitelistSkipped(
                    block.source_ip.clone(),
                    "TTL expired but manual ACL exists".to_string()
                ));
                continue;
            }
            let ip_version = ip_version_from_str(&block.source_ip)?;
            self.db
                .commit_soar_unblock_to_db(block.id, ip_version, &block.source_ip)
                .await?;
            self.soar_engine.decrement_block_count();
            committed_unblocks.push(block.source_ip.clone());
        }

        let (unblocked, failed) = self.unblock_committed_blocks(committed_unblocks).await?;
        removed += unblocked;
        skipped += failed;

        if removed > 0 || skipped > 0 {
            log!(SoarLog::TtlSweepComplete(removed, skipped));
        }

        Ok(())
    }

    async fn unblock_committed_blocks(&self, source_ips: Vec<String>) -> Result<(u32, u32), Error> {
        let access_control = Arc::clone(&self.access_control);
        let mut results = stream::iter(source_ips.into_iter().map(|source_ip| {
            let access_control = Arc::clone(&access_control);
            async move {
                let result = unblock_ip_blocking(access_control, source_ip.clone()).await;
                (source_ip, result)
            }
        }))
        .buffer_unordered(TTL_UNBLOCK_CONCURRENCY);

        let mut removed = 0u32;
        let mut skipped = 0u32;

        while let Some((source_ip, result)) = results.next().await {
            if let Err(e) = result {
                log!(SoarLog::RecoveryFailed(
                    source_ip.clone(),
                    format!("unblock failed: {}", e)
                ));
                self.db.insert_pending_unblock(&source_ip).await?;
                skipped += 1;
                continue;
            }

            removed += 1;
        }

        Ok((removed, skipped))
    }
}

async fn unblock_ip_blocking(access_control: Arc<dyn AccessControlPort>, source_ip: String) -> Result<(), Error> {
    spawn_blocking(move || access_control.unblock_ip(&source_ip))
        .await
        .map_err(|e| SoarError::ActionFailed("unblock_ip", e))?
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    use arc_swap::ArcSwap;
    use parking_lot::Mutex;

    use super::*;
    use crate::adapter::persistence::Database;
    use crate::core::common::config_loader::{load_app_config, seed_config_defaults};
    use crate::core::response::engine::SoarEngineDeps;
    use crate::domain::common::config::notification::SmtpConfig;
    use crate::domain::data_plane::acl_rule::AclRuleView;
    use crate::domain::data_plane::direction::FlowDirection;
    use crate::domain::data_plane::error::EbpfError;
    use crate::domain::data_plane::ip_version::IpVersion;
    use crate::domain::data_plane::list_type::ListType;
    use crate::interface::reporting::email_sender::{EmailSender, EmailSenderFactory};
    use crate::interface::response::soar::SoarControlRepo;
    use crate::interface::response::webhook_sender::WebhookSender;
    use crate::interface::system::secret_store::SecretStorePort;

    const EXPIRED_AT: &str = "2000-01-01 00:00:00";
    const SOURCE_IP: &str = "198.51.100.10";

    struct MockAccessControl {
        unblocked_ips: Mutex<Vec<String>>,
        should_fail: AtomicBool,
    }

    impl MockAccessControl {
        fn new(should_fail: bool) -> Self {
            Self {
                unblocked_ips: Mutex::new(Vec::new()),
                should_fail: AtomicBool::new(should_fail),
            }
        }
    }

    impl AccessControlPort for MockAccessControl {
        fn block_ip(&self, _ip: &str) -> Result<(), Error> {
            Ok(())
        }

        fn unblock_ip(&self, ip: &str) -> Result<(), Error> {
            if self.should_fail.load(Ordering::SeqCst) {
                Err(EbpfError::UnknownError)?;
            }
            self.unblocked_ips.lock().push(ip.to_string());
            Ok(())
        }
    }

    struct NoopEmailSenderFactory;

    #[async_trait::async_trait]
    impl EmailSenderFactory for NoopEmailSenderFactory {
        async fn build_smtp_sender(
            &self,
            _cfg: &SmtpConfig,
            _secrets: Option<&dyn SecretStorePort>,
        ) -> Result<Option<Box<dyn EmailSender>>, Error> {
            Ok(None)
        }
    }

    struct NoopWebhookSender;

    #[async_trait::async_trait]
    impl WebhookSender for NoopWebhookSender {
        async fn post_json(&self, _url: &str, _timeout_secs: u64, _payload: &serde_json::Value) -> Result<u16, Error> {
            Ok(200)
        }
    }

    async fn test_db() -> Arc<Database> {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        seed_config_defaults(&*db).await.expect("seed config defaults");
        db
    }

    async fn test_scheduler(
        db: Arc<Database>,
        access_control: Arc<MockAccessControl>,
    ) -> (TtlScheduler, Arc<SoarEngine>) {
        let cfg = load_app_config(&*db).await.expect("load config");
        let engine = Arc::new(
            SoarEngine::new(SoarEngineDeps {
                db: db.clone() as Arc<dyn SoarControlRepo>,
                config: Arc::new(ArcSwap::from_pointee(cfg)),
                access_control: access_control.clone(),
                alert_notifier: None,
                geoip: None,
                rate_limit: None,
                enforce_level_cache: Arc::new(AtomicU8::new(2)),
                secrets: None,
                email_sender_factory: Arc::new(NoopEmailSenderFactory),
                webhook_sender: Arc::new(NoopWebhookSender),
            })
            .await
            .expect("soar engine"),
        );
        let scheduler = TtlScheduler::new(db as Arc<dyn SoarControlRepo>, access_control, engine.clone());
        (scheduler, engine)
    }

    fn acl_contains(rules: &[AclRuleView], ip: &str) -> bool {
        rules.iter().any(|rule| {
            rule.ip_address == ip && rule.direction == FlowDirection::Source && rule.list_type == ListType::Black
        })
    }

    #[tokio::test]
    async fn ttl_sweep_preserves_manual_acl_rule_for_expired_soar_block() {
        let db = test_db().await;
        let block_id = db
            .commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, EXPIRED_AT)
            .await
            .expect("insert expired block");
        db.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Source,
            ListType::Black,
            SOURCE_IP,
            0,
            true,
        )
        .await
        .expect("manual ACL should preserve block");
        let access_control = Arc::new(MockAccessControl::new(false));
        let (scheduler, engine) = test_scheduler(db.clone(), access_control.clone()).await;
        engine.matcher.active_block_count.store(1, Ordering::SeqCst);

        scheduler.sweep().await.expect("ttl sweep");

        assert!(
            access_control.unblocked_ips.lock().is_empty(),
            "manual ACL ownership must skip data-plane unblock"
        );
        assert!(
            db.list_expired_soar_blocks().await.expect("expired blocks").is_empty(),
            "expired SOAR record should be marked unblocked"
        );
        assert!(
            acl_contains(&db.list_acl_rules().await.expect("acl rules"), SOURCE_IP),
            "manual ACL row must remain after SOAR TTL expiry"
        );
        assert_eq!(
            engine.matcher.active_block_count.load(Ordering::SeqCst),
            0,
            "SOAR active-block counter should decrement once"
        );
        assert!(db.find_soar_block_by_id(block_id).await.expect("find block").is_some());
    }

    #[tokio::test]
    async fn ttl_sweep_records_pending_unblock_after_durable_commit_when_data_plane_unblock_fails() {
        let db = test_db().await;
        db.commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, EXPIRED_AT)
            .await
            .expect("insert expired block");
        let access_control = Arc::new(MockAccessControl::new(true));
        let (scheduler, engine) = test_scheduler(db.clone(), access_control.clone()).await;
        engine.matcher.active_block_count.store(1, Ordering::SeqCst);

        scheduler.sweep().await.expect("ttl sweep");

        let pending = db.list_pending_unblocks().await.expect("pending unblocks");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_ip, SOURCE_IP);
        assert!(
            db.list_expired_soar_blocks().await.expect("expired blocks").is_empty(),
            "durable unblock should not leave SOAR block active after eBPF retry is queued"
        );
        assert!(
            !acl_contains(&db.list_acl_rules().await.expect("acl rules"), SOURCE_IP),
            "SOAR-owned ACL row should be removed once durable unblock commits"
        );
        assert!(
            access_control.unblocked_ips.lock().is_empty(),
            "failing data-plane call should not record a successful unblock"
        );
        assert_eq!(
            engine.matcher.active_block_count.load(Ordering::SeqCst),
            0,
            "SOAR active-block counter follows durable state after retry is queued"
        );
    }

    #[tokio::test]
    async fn ttl_sweep_deletes_soar_owned_acl_only_after_data_plane_unblock_succeeds() {
        let db = test_db().await;
        db.commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, EXPIRED_AT)
            .await
            .expect("insert expired block");
        let access_control = Arc::new(MockAccessControl::new(false));
        let (scheduler, engine) = test_scheduler(db.clone(), access_control.clone()).await;
        engine.matcher.active_block_count.store(1, Ordering::SeqCst);

        scheduler.sweep().await.expect("ttl sweep");

        assert_eq!(access_control.unblocked_ips.lock().as_slice(), &[SOURCE_IP.to_string()]);
        assert!(
            db.list_expired_soar_blocks().await.expect("expired blocks").is_empty(),
            "successful unblock should mark SOAR record unblocked"
        );
        assert!(
            !acl_contains(&db.list_acl_rules().await.expect("acl rules"), SOURCE_IP),
            "SOAR-owned ACL row should be removed after data-plane unblock succeeds"
        );
        assert!(
            db.list_pending_unblocks().await.expect("pending unblocks").is_empty(),
            "successful unblock should not enqueue retry work"
        );
        assert_eq!(
            engine.matcher.active_block_count.load(Ordering::SeqCst),
            0,
            "active-block counter should decrement after successful unblock"
        );
    }
}
