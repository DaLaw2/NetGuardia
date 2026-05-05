use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::Semaphore;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::core::response::matcher::PlaybookMatcher;
use crate::core::response::rate_limit_owner::RateLimitOwnerHandle;
use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::detection::attack_type::canonical_from_str;
use crate::domain::response::condition::{ConditionType, PlaybookCondition};
use crate::domain::response::log::SoarLog;
use crate::domain::response::playbook::{Playbook, PlaybookAction};
use crate::interface::access_control::AccessControlPort;
use crate::interface::app_repo::AppRepo;
use crate::interface::email_sender::EmailSenderFactory;
use crate::interface::geo_lookup::GeoLookup;
use crate::interface::notification::AlertNotifier;
use crate::interface::rate_limit_api::RateLimitPort;
use crate::interface::secret_store::SecretStorePort;

pub struct SoarEngine {
    pub(super) db: Arc<dyn AppRepo>,
    pub(super) access_control: Arc<dyn AccessControlPort>,
    pub(super) matcher: PlaybookMatcher,
    pub(super) alert_notifier: Option<Arc<dyn AlertNotifier>>,
    pub(super) geoip: Option<Arc<dyn GeoLookup>>,
    pub(super) rate_limit: Option<RateLimitOwnerHandle>,
    pub(super) enforce_level_cache: Arc<AtomicU8>,
    pub(super) secrets: Option<Arc<dyn SecretStorePort>>,
    pub(super) email_sender_factory: Arc<dyn EmailSenderFactory>,
}

pub struct SoarEngineDeps {
    pub db: Arc<dyn AppRepo>,
    pub config: Arc<ArcSwap<AppConfig>>,
    pub access_control: Arc<dyn AccessControlPort>,
    pub alert_notifier: Option<Arc<dyn AlertNotifier>>,
    pub geoip: Option<Arc<dyn GeoLookup>>,
    pub rate_limit: Option<Arc<dyn RateLimitPort>>,
    pub enforce_level_cache: Arc<AtomicU8>,
    pub secrets: Option<Arc<dyn SecretStorePort>>,
    pub email_sender_factory: Arc<dyn EmailSenderFactory>,
}

impl SoarEngine {
    pub async fn new(deps: SoarEngineDeps) -> Result<Self, Error> {
        let SoarEngineDeps {
            db,
            config,
            access_control,
            alert_notifier,
            geoip,
            rate_limit,
            enforce_level_cache,
            secrets,
            email_sender_factory,
        } = deps;
        let soar_cfg = config.load();
        let rate_limit_channel = soar_cfg.soar.rate_limit_cmd_channel_capacity;
        let freq_max_keys = soar_cfg.soar.frequency_max_tracked_keys;
        let freq_max_events_per_key = soar_cfg.soar.frequency_max_events_per_key;
        let freq_retention_secs = soar_cfg.soar.frequency_retention_secs;
        drop(soar_cfg);
        let rate_limit_owner = rate_limit.map(|rl| RateLimitOwnerHandle::spawn(rl, config.clone(), rate_limit_channel));
        let matcher = PlaybookMatcher::new(config, freq_max_keys, freq_max_events_per_key, freq_retention_secs);
        let engine = Self {
            db,
            access_control,
            matcher,
            alert_notifier,
            geoip,
            rate_limit: rate_limit_owner,
            enforce_level_cache,
            secrets,
            email_sender_factory,
        };
        engine.reload_cache().await?;
        Ok(engine)
    }

    /// Load playbooks and admin whitelist from DB into memory.
    pub async fn reload_cache(&self) -> Result<(), Error> {
        let views = self.db.list_playbooks().await?;
        let mut playbooks: Vec<Playbook> = Vec::new();

        for view in views {
            let mut actions: Vec<PlaybookAction> = Vec::new();
            for a in view.actions {
                actions.push(PlaybookAction {
                    action_order: a.action_order,
                    action_type: a.action_type,
                    params: a.params,
                });
            }

            let mut conditions: Vec<PlaybookCondition> = Vec::new();
            for c in view.conditions {
                let Ok(ctype) = c.condition_type.parse::<ConditionType>() else {
                    continue;
                };
                // Validate operator at load time to prevent silent fallback to defaults
                let valid = match ctype {
                    ConditionType::Threshold => matches!(c.operator.as_str(), ">=" | "<="),
                    ConditionType::SourceCountry | ConditionType::IpPattern => {
                        matches!(c.operator.as_str(), "in" | "not_in")
                    }
                    ConditionType::RepeatOffender => c.operator == "==",
                    ConditionType::Frequency => c.operator == ">=",
                    ConditionType::MultiSourceMin => c.operator == ">=",
                    ConditionType::SingleSourceHigh => c.operator == ">=",
                    ConditionType::FusedConfidenceAbove => matches!(c.operator.as_str(), ">=" | "<="),
                };
                if !valid {
                    log!(SoarLog::InvalidConditionOperator(
                        view.name.clone(),
                        c.condition_type.clone(),
                        c.operator.clone(),
                    ));
                    continue;
                }
                conditions.push(PlaybookCondition {
                    condition_type: ctype,
                    operator: c.operator,
                    value: c.value,
                    value2: c.value2,
                });
            }

            playbooks.push(Playbook {
                id: view.id,
                name: view.name,
                enabled: view.enabled,
                trigger_event: view.trigger_event,
                cooldown_secs: view.cooldown_secs,
                actions,
                conditions,
            });
        }

        // Warn on playbooks whose trigger_event isn't in the canonical
        // dictionary — those won't ever match a fused event and usually
        // signal a typo or stale pre-canonicalization playbook.
        for pb in &playbooks {
            if canonical_from_str(&pb.trigger_event).is_none() {
                log!(SoarLog::NonCanonicalTriggerEvent(
                    pb.name.clone(),
                    pb.trigger_event.clone(),
                ));
            }
        }

        let playbook_count = playbooks.len();
        // Wrap each playbook in Arc so the per-event matcher hot path can
        // hand out cheap Arc clones instead of cloning the full Playbook
        // (with its nested Vec<PlaybookCondition> / Vec<PlaybookAction>).
        let playbooks: Vec<Arc<Playbook>> = playbooks.into_iter().map(Arc::new).collect();
        self.matcher.playbooks.store(Arc::new(playbooks));

        // Load admin whitelist
        let whitelist = self.db.list_admin_whitelist().await?;
        let whitelist: HashSet<String> = whitelist.into_iter().collect();
        let whitelist_count = whitelist.len();
        self.matcher.admin_whitelist.store(Arc::new(whitelist));

        // Initialize block counter from DB
        let count = self.db.count_active_soar_blocks().await?;
        self.matcher.active_block_count.store(count, Ordering::SeqCst);

        log!(SoarLog::CacheLoaded(playbook_count, whitelist_count, count));

        Ok(())
    }

    /// Subscribe to ThreatDetectedEvent and start processing.
    pub fn start(self: Arc<Self>, threat_rx: broadcast::Receiver<ThreatDetectedEvent>) {
        tokio::spawn(async move {
            Self::event_loop(self, threat_rx).await;
        });
    }

    async fn event_loop(self: Arc<Self>, mut rx: broadcast::Receiver<ThreatDetectedEvent>) {
        log!(SoarLog::EngineStarted);
        let concurrency = self.matcher.config.load().soar.handle_concurrency.max(1);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Bounded fan-out: hold one permit per in-flight handler.
                    // When handle_concurrency permits are already held, this
                    // await blocks the recv loop, which is the backpressure
                    // signal — broadcast surfaces it as Lagged on overflow.
                    let permit = match Arc::clone(&semaphore).acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    let engine = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = engine.handle_threat_event(&event).await {
                            log!(SoarLog::EventHandlingFailed(e.to_string()));
                        }
                        drop(permit);
                    });
                }
                Err(RecvError::Lagged(n)) => {
                    log!(SoarLog::ReceiverLagged(n));
                }
                Err(RecvError::Closed) => {
                    log!(SoarLog::ChannelClosed);
                    break;
                }
            }
        }
    }

    /// Handle a single threat event: find matching playbooks and execute them.
    async fn handle_threat_event(&self, event: &ThreatDetectedEvent) -> Result<(), Error> {
        let matching = self.find_matching_playbooks(event);

        if matching.is_empty() {
            // PlaybookNotFound fallback: only if source_ip is present
            if !event.source_ip.is_empty() {
                log!(SoarLog::FallbackTriggered(event.attack_type.clone()));
                self.execute_fallback(event).await?;
            }
            return Ok(());
        }

        for playbook in matching {
            if let Err(e) = self.execute_playbook(&playbook, event).await {
                log!(SoarLog::PlaybookError(playbook.name.clone(), e.to_string()));
            }
        }

        Ok(())
    }

    /// Recover active block rules on startup by re-applying to eBPF.
    pub async fn recover_active_blocks(&self) -> Result<(), Error> {
        // First, retry any pending unblocks from previous orphan failures
        self.retry_pending_unblocks().await;

        let active_blocks = self.db.list_active_soar_blocks().await?;
        let count = active_blocks.len();

        for block in &active_blocks {
            // Preserve original error-swallowing behavior during recovery
            if let Err(e) = self.access_control.block_ip(&block.source_ip) {
                log!(SoarLog::RecoveryFailed(block.source_ip.clone(), e.to_string()));
            }
        }

        if count > 0 {
            log!(SoarLog::RecoveryComplete(count));
        }

        Ok(())
    }

    /// Retry pending unblocks that failed during previous runs.
    async fn retry_pending_unblocks(&self) {
        let pending = match self.db.list_pending_unblocks().await {
            Ok(p) => p,
            Err(e) => {
                log!(SoarLog::EventHandlingFailed(format!(
                    "Failed to load pending unblocks: {}",
                    e
                )));
                return;
            }
        };

        for pu in pending {
            if pu.retry_count >= self.matcher.config.load().soar.max_pending_unblock_retries {
                log!(SoarLog::EventHandlingFailed(format!(
                    "Giving up on pending unblock for IP {} after {} retries",
                    pu.source_ip, pu.retry_count
                )));
                // Remove from queue to avoid infinite retries
                let _ = self.db.delete_pending_unblock(pu.id).await;
                continue;
            }

            match self.access_control.unblock_ip(&pu.source_ip) {
                Ok(()) => {
                    let _ = self.db.delete_pending_unblock(pu.id).await;
                    log!(SoarLog::EventHandlingFailed(format!(
                        "Successfully unblocked orphan IP {} on retry #{}",
                        pu.source_ip,
                        pu.retry_count + 1
                    )));
                }
                Err(e) => {
                    let _ = self.db.increment_pending_unblock_retry(pu.id).await;
                    log!(SoarLog::EventHandlingFailed(format!(
                        "Retry #{} failed to unblock orphan IP {}: {}",
                        pu.retry_count + 1,
                        pu.source_ip,
                        e
                    )));
                }
            }
        }
    }

    /// Restore original rate limits if the TTL has expired.
    /// Called by TTL scheduler on each sweep.
    pub async fn check_rate_limit_restoration(&self) -> Result<(), Error> {
        match &self.rate_limit {
            Some(owner) => owner.restore_if_expired().await,
            None => Ok(()),
        }
    }

    pub fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Arc<Playbook>> {
        self.matcher.find_matching_playbooks(event)
    }

    #[cfg(test)]
    pub fn evaluate_conditions(&self, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        self.matcher.evaluate_conditions(pb, event)
    }

    pub fn is_cooldown_active(&self, playbook_id: i64, source_ip: &str, cooldown_secs: i64) -> bool {
        self.matcher.is_cooldown_active(playbook_id, source_ip, cooldown_secs)
    }

    pub fn record_cooldown(&self, playbook_id: i64, source_ip: &str) {
        self.matcher.record_cooldown(playbook_id, source_ip)
    }

    pub fn cleanup_expired_cooldowns(&self) {
        self.matcher.cleanup_expired_cooldowns()
    }

    pub fn decrement_block_count(&self) {
        self.matcher.decrement_block_count()
    }

    pub fn dry_run(&self, event: &ThreatDetectedEvent) -> Vec<crate::domain::response::dry_run::DryRunMatch> {
        self.matcher.dry_run(event)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use chrono::{Duration as ChronoDuration, Utc};
    use parking_lot::Mutex;

    use super::*;
    use crate::domain::common::config::notification::SmtpConfig;
    use crate::domain::common::event::DetectionSource;
    use crate::domain::data_plane::error::EbpfError;
    use crate::interface::email_sender::{
        EmailSender as EmailSenderTrait, EmailSenderFactory as EmailSenderFactoryTrait,
    };

    struct NoopEmailSenderFactory;

    #[async_trait::async_trait]
    impl EmailSenderFactoryTrait for NoopEmailSenderFactory {
        async fn build_smtp_sender(
            &self,
            _cfg: &SmtpConfig,
            _secrets: Option<&dyn crate::interface::secret_store::SecretStorePort>,
        ) -> Result<Option<Box<dyn EmailSenderTrait>>, Error> {
            Ok(None)
        }
    }

    /// Mock AccessControlPort that records calls.
    struct MockAccessControl {
        blocked_ips: Mutex<Vec<String>>,
        unblocked_ips: Mutex<Vec<String>>,
        should_fail: AtomicBool,
    }

    impl MockAccessControl {
        fn new() -> Self {
            Self {
                blocked_ips: Mutex::new(Vec::new()),
                unblocked_ips: Mutex::new(Vec::new()),
                should_fail: AtomicBool::new(false),
            }
        }
    }

    impl AccessControlPort for MockAccessControl {
        fn block_ip(&self, ip: &str) -> Result<(), Error> {
            if self.should_fail.load(Ordering::SeqCst) {
                Err(EbpfError::UnknownError)?;
            }
            self.blocked_ips.lock().push(ip.to_string());
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

    async fn test_db() -> Arc<crate::adapter::persistence::Database> {
        use crate::adapter::persistence::Database;
        Arc::new(Database::new(":memory:").await.expect("Failed to create test database"))
    }

    async fn test_engine(ac: Arc<dyn AccessControlPort>) -> SoarEngine {
        let db = test_db().await;
        db.seed_default_playbooks().await.ok();
        db.set_config_value("enforce_mode", "enforce").await.ok();
        let cache = Arc::new(AtomicU8::new(2));
        AppConfig::seed_config_defaults(&*db)
            .await
            .expect("seed config defaults");
        let cfg = AppConfig::from_config_repo(&*db).await.expect("load config");
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        SoarEngine::new(SoarEngineDeps {
            db: db as Arc<dyn AppRepo>,
            config,
            access_control: ac,
            alert_notifier: None,
            geoip: None,
            rate_limit: None,
            enforce_level_cache: cache,
            secrets: None,
            email_sender_factory: Arc::new(NoopEmailSenderFactory),
        })
        .await
        .expect("Failed to create SOAR engine")
    }

    #[tokio::test]
    async fn block_ip_calls_access_control_port() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock.clone()).await;

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence: 0.95,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![DetectionSource::ML],
            active_source_count: 1,
            fused_confidence: 0.95,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        let action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": 600}),
        };

        let result = engine.execute_action(&action, &event, 1).await;
        assert!(result.is_ok(), "block_ip action should succeed");

        let blocked = mock.blocked_ips.lock();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0], "1.2.3.4");
    }

    #[tokio::test]
    async fn block_ip_ipv6_calls_access_control_port() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock.clone()).await;

        let event = ThreatDetectedEvent {
            source_ip: "::1".to_string(),
            dest_ip: "::2".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence: 0.9,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![DetectionSource::ML],
            active_source_count: 1,
            fused_confidence: 0.95,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        let action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": 300}),
        };

        let result = engine.execute_action(&action, &event, 1).await;
        assert!(result.is_ok());

        let blocked = mock.blocked_ips.lock();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0], "::1");
    }

    #[tokio::test]
    async fn recover_active_blocks_uses_port() {
        let mock = Arc::new(MockAccessControl::new());
        let db = test_db().await;
        db.seed_default_playbooks().await.ok();

        // Insert a fake active block
        let expires = (Utc::now() + ChronoDuration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.commit_soar_block_to_db("192.168.1.100", 4, 1, &expires).await.ok();

        let cache = Arc::new(AtomicU8::new(2));
        AppConfig::seed_config_defaults(&*db)
            .await
            .expect("seed config defaults");
        let cfg = AppConfig::from_config_repo(&*db).await.expect("load config");
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let engine = SoarEngine::new(SoarEngineDeps {
            db: db as Arc<dyn AppRepo>,
            config,
            access_control: mock.clone(),
            alert_notifier: None,
            geoip: None,
            rate_limit: None,
            enforce_level_cache: cache,
            secrets: None,
            email_sender_factory: Arc::new(NoopEmailSenderFactory),
        })
        .await
        .expect("Failed to create engine");
        engine.recover_active_blocks().await.expect("Recovery should succeed");

        let blocked = mock.blocked_ips.lock();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0], "192.168.1.100");
    }

    #[tokio::test]
    async fn recover_logs_warning_on_failure() {
        let mock = Arc::new(MockAccessControl::new());
        mock.should_fail.store(true, Ordering::SeqCst);
        let db = test_db().await;
        db.seed_default_playbooks().await.ok();

        let expires = (Utc::now() + ChronoDuration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.commit_soar_block_to_db("10.0.0.1", 4, 1, &expires).await.ok();

        let cache = Arc::new(AtomicU8::new(2));
        AppConfig::seed_config_defaults(&*db)
            .await
            .expect("seed config defaults");
        let cfg = AppConfig::from_config_repo(&*db).await.expect("load config");
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let engine = SoarEngine::new(SoarEngineDeps {
            db: db as Arc<dyn AppRepo>,
            config,
            access_control: mock.clone(),
            alert_notifier: None,
            geoip: None,
            rate_limit: None,
            enforce_level_cache: cache,
            secrets: None,
            email_sender_factory: Arc::new(NoopEmailSenderFactory),
        })
        .await
        .expect("Failed to create engine");

        // Should not panic — errors are logged, not propagated
        let result = engine.recover_active_blocks().await;
        assert!(result.is_ok(), "Recovery should succeed even when block_ip fails");

        // No IPs should have been blocked (mock fails)
        assert!(mock.blocked_ips.lock().is_empty());
    }

    #[tokio::test]
    async fn block_ip_respects_cap() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock.clone()).await;

        // Set counter to max (default cap is 100)
        engine.matcher.active_block_count.store(100, Ordering::SeqCst);

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence: 0.95,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![DetectionSource::ML],
            active_source_count: 1,
            fused_confidence: 0.95,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        let action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": 600}),
        };

        let result = engine.execute_action(&action, &event, 1).await;
        assert!(result.is_err(), "Should fail when cap is reached");
        assert!(
            mock.blocked_ips.lock().is_empty(),
            "Should not call block_ip when cap reached"
        );
    }

    #[tokio::test]
    async fn cooldown_prevents_duplicate_execution() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock.clone()).await;

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "c2_beacon".to_string(),
            confidence: 0.95,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![DetectionSource::Suricata, DetectionSource::ML],
            active_source_count: 2,
            fused_confidence: 0.97,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        // The multi-source c2_beacon seed playbook matches a 2-source fusion
        // event and its first action is block_ip.
        let playbooks = engine.find_matching_playbooks(&event);
        assert!(!playbooks.is_empty(), "Should have matching playbooks");

        let pb = &playbooks[0];

        // First execution should succeed
        let result = engine.execute_playbook(pb, &event).await;
        assert!(result.is_ok());
        assert!(!mock.blocked_ips.lock().is_empty());

        // Second execution with same IP should be skipped (cooldown)
        let blocked_before = mock.blocked_ips.lock().len();
        let result = engine.execute_playbook(pb, &event).await;
        assert!(result.is_ok()); // Cooldown returns Ok, just skips
        let blocked_after = mock.blocked_ips.lock().len();
        assert_eq!(blocked_before, blocked_after, "Should not block again during cooldown");
    }

    #[tokio::test]
    async fn whitelist_prevents_execution() {
        let mock = Arc::new(MockAccessControl::new());
        let db = test_db().await;
        db.seed_default_playbooks().await.ok();
        db.insert_admin_whitelist("1.2.3.4").await.ok();

        let cache = Arc::new(AtomicU8::new(2));
        AppConfig::seed_config_defaults(&*db)
            .await
            .expect("seed config defaults");
        let cfg = AppConfig::from_config_repo(&*db).await.expect("load config");
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let engine = SoarEngine::new(SoarEngineDeps {
            db: db as Arc<dyn AppRepo>,
            config,
            access_control: mock.clone(),
            alert_notifier: None,
            geoip: None,
            rate_limit: None,
            enforce_level_cache: cache,
            secrets: None,
            email_sender_factory: Arc::new(NoopEmailSenderFactory),
        })
        .await
        .expect("Failed to create engine");

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "c2_beacon".to_string(),
            confidence: 0.95,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![DetectionSource::Suricata, DetectionSource::ML],
            active_source_count: 2,
            fused_confidence: 0.97,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        };

        let playbooks = engine.find_matching_playbooks(&event);
        assert!(!playbooks.is_empty());

        let result = engine.execute_playbook(&playbooks[0], &event).await;
        assert!(result.is_ok());
        assert!(
            mock.blocked_ips.lock().is_empty(),
            "Whitelisted IP should not be blocked"
        );
    }

    #[tokio::test]
    async fn decrement_block_count_no_underflow() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;

        // Start at 0
        assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

        // Decrement should not underflow
        engine.decrement_block_count();
        assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

        // Set to 2, decrement twice → should be 0
        engine.matcher.active_block_count.store(2, Ordering::SeqCst);
        engine.decrement_block_count();
        assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 1);
        engine.decrement_block_count();
        assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

        // One more decrement should stay at 0
        engine.decrement_block_count();
        assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reload_cache_loads_playbooks_via_join() {
        let mock = Arc::new(MockAccessControl::new());
        let db = test_db().await;
        db.seed_default_playbooks().await.ok();

        let cache = Arc::new(AtomicU8::new(0));
        AppConfig::seed_config_defaults(&*db)
            .await
            .expect("seed config defaults");
        let cfg = AppConfig::from_config_repo(&*db).await.expect("load config");
        let config = Arc::new(ArcSwap::from_pointee(cfg));
        let engine = SoarEngine::new(SoarEngineDeps {
            db: db.clone() as Arc<dyn AppRepo>,
            config,
            access_control: mock,
            alert_notifier: None,
            geoip: None,
            rate_limit: None,
            enforce_level_cache: cache,
            secrets: None,
            email_sender_factory: Arc::new(NoopEmailSenderFactory),
        })
        .await
        .expect("Failed to create engine");

        // Should have loaded default playbooks
        let count = engine.matcher.playbooks.load().len();
        assert!(count > 0, "Should have loaded default playbooks");

        // Add a new playbook directly to DB
        db.insert_playbook("test_pb", "port_scan", None, None, None, 60)
            .await
            .ok();

        // Cache should not have it yet
        assert_eq!(engine.matcher.playbooks.load().len(), count);

        // After reload, should have one more
        engine.reload_cache().await.expect("reload should succeed");
        assert_eq!(engine.matcher.playbooks.load().len(), count + 1);
    }

    fn test_event(confidence: f32, country: Option<&str>, ip: &str, repeat: bool) -> ThreatDetectedEvent {
        ThreatDetectedEvent {
            source_ip: ip.to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence,
            flow_count: 1,
            packet_rate: 100.0,
            protocol: 6,
            geoip_country: country.map(|s| s.to_string()),
            is_repeat_offender: repeat,
            sources: vec![DetectionSource::ML],
            active_source_count: 1,
            fused_confidence: 0.95,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        }
    }

    fn make_playbook(conditions: Vec<PlaybookCondition>) -> Playbook {
        Playbook {
            id: 999,
            name: "test-playbook".to_string(),
            trigger_event: "threat_detected".to_string(),
            cooldown_secs: 60,
            enabled: true,
            actions: vec![],
            conditions,
        }
    }

    #[tokio::test]
    async fn condition_threshold_gte_passes() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: ">=".to_string(),
            value: "0.9".to_string(),
            value2: None,
        }]);
        let event = test_event(0.95, None, "1.2.3.4", false);
        assert!(engine.evaluate_conditions(&pb, &event));
    }

    #[tokio::test]
    async fn condition_threshold_gte_fails() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: ">=".to_string(),
            value: "0.9".to_string(),
            value2: None,
        }]);
        let event = test_event(0.85, None, "1.2.3.4", false);
        assert!(!engine.evaluate_conditions(&pb, &event));
    }

    #[tokio::test]
    async fn condition_threshold_lte() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: "<=".to_string(),
            value: "0.5".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.3, None, "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.7, None, "1.2.3.4", false)));
    }

    #[tokio::test]
    async fn condition_source_country_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::SourceCountry,
            operator: "in".to_string(),
            value: "CN, RU, KP".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, Some("CN"), "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, Some("US"), "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, None, "1.2.3.4", false)));
    }

    #[tokio::test]
    async fn condition_source_country_not_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::SourceCountry,
            operator: "not_in".to_string(),
            value: "US, TW".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, Some("CN"), "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, Some("TW"), "1.2.3.4", false)));
    }

    #[tokio::test]
    async fn condition_ip_pattern_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::IpPattern,
            operator: "in".to_string(),
            value: "10.0.0.0/8".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, None, "10.1.2.3", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, None, "192.168.1.1", false)));
    }

    #[tokio::test]
    async fn condition_repeat_offender() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::RepeatOffender,
            operator: "==".to_string(),
            value: "true".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, None, "1.2.3.4", true)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, None, "1.2.3.4", false)));
    }

    #[tokio::test]
    async fn condition_and_logic_all_must_pass() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![
            PlaybookCondition {
                condition_type: ConditionType::Threshold,
                operator: ">=".to_string(),
                value: "0.9".to_string(),
                value2: None,
            },
            PlaybookCondition {
                condition_type: ConditionType::SourceCountry,
                operator: "in".to_string(),
                value: "CN".to_string(),
                value2: None,
            },
        ]);
        // Both conditions met
        assert!(engine.evaluate_conditions(&pb, &test_event(0.95, Some("CN"), "1.2.3.4", false)));
        // Threshold met but country not
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.95, Some("US"), "1.2.3.4", false)));
        // Country met but threshold not
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.5, Some("CN"), "1.2.3.4", false)));
    }

    #[tokio::test]
    async fn frequency_condition_counts_events() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock).await;
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Frequency,
            operator: ">=".to_string(),
            value: "3".to_string(),
            value2: Some("60".to_string()),
        }]);
        let event = test_event(0.9, None, "1.2.3.4", false);
        assert!(!engine.evaluate_conditions(&pb, &event)); // count=1
        assert!(!engine.evaluate_conditions(&pb, &event)); // count=2
        assert!(engine.evaluate_conditions(&pb, &event)); // count=3 ✓
    }
}
