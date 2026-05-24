use std::net::IpAddr;
use std::sync::Arc;

use crate::common::error::Error;
use crate::common::utils::ip_address::ip_version_from_str;
use crate::core::response::engine::SoarEngine;
use crate::domain::data_plane::error::EbpfError;
use crate::domain::response::error::SoarError;
use crate::interface::data_plane::access_control::AccessControlPort;
use crate::interface::response::playbook_data::{
    ActiveBlockView, CreatePlaybookInput, ExecutionView, PlaybookView, UpdatePlaybookInput,
};
use crate::interface::response::soar::SoarControlRepo;

pub struct PlaybookService {
    db: Arc<dyn SoarControlRepo>,
    soar_engine: Arc<SoarEngine>,
    access_control: Arc<dyn AccessControlPort>,
}

impl PlaybookService {
    pub fn new(
        db: Arc<dyn SoarControlRepo>,
        soar_engine: Arc<SoarEngine>,
        access_control: Arc<dyn AccessControlPort>,
    ) -> Self {
        Self {
            db,
            soar_engine,
            access_control,
        }
    }

    pub async fn list_playbooks(&self) -> Result<Vec<PlaybookView>, Error> {
        self.db.list_playbooks().await
    }

    pub async fn create_playbook(&self, input: &CreatePlaybookInput) -> Result<i64, Error> {
        let playbook_id = self
            .db
            .insert_playbook_atomic(input, &input.actions, &input.conditions)
            .await?;
        self.soar_engine.reload_cache().await?;
        Ok(playbook_id)
    }

    pub async fn update_playbook(&self, id: i64, input: &CreatePlaybookInput) -> Result<bool, Error> {
        let row = UpdatePlaybookInput {
            name: input.name.clone(),
            trigger_event: input.trigger_event.clone(),
            condition_threshold: input.condition_threshold,
            condition_count: input.condition_count,
            condition_window_secs: input.condition_window_secs,
            cooldown_secs: input.cooldown_secs,
        };
        let updated = self
            .db
            .update_playbook_atomic(id, &row, &input.actions, &input.conditions)
            .await?;
        if !updated {
            return Ok(false);
        }
        self.soar_engine.reload_cache().await?;
        Ok(true)
    }

    pub async fn toggle_playbook(&self, id: i64, enabled: bool) -> Result<bool, Error> {
        let updated = self.db.update_playbook_enabled(id, enabled).await?;
        if updated {
            self.soar_engine.reload_cache().await?;
        }
        Ok(updated)
    }

    pub async fn delete_playbook(&self, id: i64) -> Result<bool, Error> {
        let deleted = self.db.delete_playbook(id).await?;
        if deleted {
            self.soar_engine.reload_cache().await?;
        }
        Ok(deleted)
    }

    pub async fn list_active_blocks(&self) -> Result<Vec<ActiveBlockView>, Error> {
        self.db.list_active_soar_blocks().await
    }

    pub async fn manual_unblock(&self, id: i64) -> Result<(), Error> {
        let block = self
            .db
            .find_soar_block_by_id(id)
            .await?
            .ok_or_else(|| SoarError::UnblockRuleNotFound(id))?;
        let source_ip = &block.source_ip;
        let has_manual_rule = self.db.has_manual_acl_rule(source_ip).await?;
        let ip_version = ip_version_from_str(source_ip)?;
        self.db.commit_soar_unblock_to_db(id, ip_version, source_ip).await?;

        self.soar_engine.decrement_block_count();

        if has_manual_rule {
            return Ok(());
        }

        if let Err(e) = self.access_control.unblock_ip(source_ip) {
            self.db
                .insert_pending_unblock(source_ip)
                .await
                .map_err(|pending_err| SoarError::PendingUnblockQueueFailed(source_ip.to_string(), pending_err))?;
            return Err(e);
        }

        Ok(())
    }

    pub async fn list_executions(&self, limit: i64) -> Result<Vec<ExecutionView>, Error> {
        self.db.list_soar_executions(limit).await
    }

    pub async fn list_whitelist(&self) -> Result<Vec<String>, Error> {
        self.db.list_admin_whitelist().await
    }

    pub async fn add_whitelist(&self, ip: &str) -> Result<(), Error> {
        let ip = normalize_admin_whitelist_ip(ip)?;
        self.db.insert_admin_whitelist(&ip).await?;
        self.soar_engine.reload_cache().await?;
        Ok(())
    }

    pub async fn remove_whitelist(&self, ip: &str) -> Result<(), Error> {
        let ip = normalize_admin_whitelist_ip(ip)?;
        self.db.delete_admin_whitelist(&ip).await?;
        self.soar_engine.reload_cache().await?;
        Ok(())
    }
}

fn normalize_admin_whitelist_ip(ip: &str) -> Result<String, Error> {
    let trimmed = ip.trim();
    let parsed = trimmed
        .parse::<IpAddr>()
        .map_err(|_| EbpfError::InvalidIpAddress(ip.to_string()))?;
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use parking_lot::Mutex;

    use super::*;
    use crate::adapter::persistence::Database;
    use crate::core::common::config_loader::{load_app_config, seed_config_defaults};
    use crate::core::response::engine::SoarEngineDeps;
    use crate::domain::common::config::notification::SmtpConfig;
    use crate::domain::data_plane::acl_rule::AclRuleView;
    use crate::domain::data_plane::direction::FlowDirection;
    use crate::domain::data_plane::ip_version::IpVersion;
    use crate::domain::data_plane::list_type::ListType;
    use crate::interface::reporting::email_sender::{EmailSender, EmailSenderFactory};
    use crate::interface::response::webhook_sender::WebhookSender;
    use crate::interface::system::secret_store::SecretStorePort;

    const SOURCE_IP: &str = "198.51.100.10";
    const ACTIVE_UNTIL: &str = "2999-01-01 00:00:00";

    #[derive(Default)]
    struct MockAccessControl {
        unblocked_ips: Mutex<Vec<String>>,
    }

    impl AccessControlPort for MockAccessControl {
        fn block_ip(&self, _ip: &str) -> Result<(), Error> {
            Ok(())
        }

        fn unblock_ip(&self, ip: &str) -> Result<(), Error> {
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

    async fn test_service(db: Arc<Database>, access_control: Arc<MockAccessControl>) -> PlaybookService {
        let cfg = load_app_config(&*db).await.expect("load config");
        let db_repo = db.clone() as Arc<dyn SoarControlRepo>;
        let access_control_port = access_control.clone() as Arc<dyn AccessControlPort>;
        let engine = Arc::new(
            SoarEngine::new(SoarEngineDeps {
                db: db_repo.clone(),
                config: Arc::new(ArcSwap::from_pointee(cfg)),
                access_control: access_control_port.clone(),
                alert_notifier: None,
                geoip: None,
                rate_limit: None,
                enforce_level_cache: Arc::new(std::sync::atomic::AtomicU8::new(2)),
                secrets: None,
                email_sender_factory: Arc::new(NoopEmailSenderFactory),
                webhook_sender: Arc::new(NoopWebhookSender),
            })
            .await
            .expect("soar engine"),
        );
        PlaybookService::new(db_repo, engine, access_control_port)
    }

    fn acl_contains(rules: &[AclRuleView], ip: &str) -> bool {
        rules.iter().any(|rule| {
            rule.ip_address == ip && rule.direction == FlowDirection::Source && rule.list_type == ListType::Black
        })
    }

    #[tokio::test]
    async fn manual_unblock_preserves_manual_acl_in_data_plane() {
        let db = test_db().await;
        let block_id = db
            .commit_soar_block_to_db(SOURCE_IP, IpVersion::V4, 1, ACTIVE_UNTIL)
            .await
            .expect("soar block");
        db.insert_acl_rule(
            IpVersion::V4,
            FlowDirection::Source,
            ListType::Black,
            SOURCE_IP,
            0,
            true,
        )
        .await
        .expect("manual acl should preserve block");
        let access_control = Arc::new(MockAccessControl::default());
        let service = test_service(db.clone(), access_control.clone()).await;

        service.manual_unblock(block_id).await.expect("manual unblock");

        assert!(
            access_control.unblocked_ips.lock().is_empty(),
            "manual ACL ownership must skip data-plane unblock"
        );
        assert!(
            db.list_active_soar_blocks().await.expect("active blocks").is_empty(),
            "SOAR block should be marked unblocked"
        );
        assert!(
            acl_contains(&db.list_acl_rules().await.expect("acl rules"), SOURCE_IP),
            "manual ACL row must remain after manual SOAR unblock"
        );
        assert!(
            db.list_pending_unblocks().await.expect("pending unblocks").is_empty(),
            "skipped data-plane unblock should not queue retry work"
        );
    }

    #[tokio::test]
    async fn whitelist_entries_are_validated_and_canonicalized() {
        let db = test_db().await;
        let access_control = Arc::new(MockAccessControl::default());
        let service = test_service(db.clone(), access_control).await;

        service
            .add_whitelist(" 2001:0db8:0000:0000:0000:0000:0000:0001 ")
            .await
            .expect("valid IPv6 whitelist entry");

        let entries = db.list_admin_whitelist().await.expect("whitelist entries");
        assert_eq!(entries, vec!["2001:db8::1"]);

        let err = service
            .add_whitelist("not an ip")
            .await
            .expect_err("invalid whitelist entry should fail");
        assert!(matches!(err, Error::Ebpf(EbpfError::InvalidIpAddress { .. })));
    }
}
