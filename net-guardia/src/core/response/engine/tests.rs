use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::Mutex;

use super::*;
use crate::adapter::persistence::Database;
use crate::core::common::config_loader::{load_app_config, seed_config_defaults};
use crate::domain::common::config::notification::SmtpConfig;
use crate::domain::common::event::{DetectionSource, ThreatDetectedEvent};
use crate::domain::data_plane::error::EbpfError;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::detection::attack_type::CanonicalAttackType;
use crate::domain::response::condition::{ConditionType, PlaybookCondition};
use crate::domain::response::playbook::{ActionType, Playbook, PlaybookAction, PlaybookActionParams};
use crate::interface::reporting::email_sender::{
    EmailSender as EmailSenderTrait, EmailSenderFactory as EmailSenderFactoryTrait,
};
use crate::interface::response::playbook_data::{ActionInput, CreatePlaybookInput};
use crate::interface::response::soar::PlaybookRepo;
use crate::interface::response::webhook_sender::WebhookSender as WebhookSenderTrait;
use crate::interface::system::secret_store::SecretStorePort;

impl SoarEngine {
    fn evaluate_conditions(&self, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        self.matcher.evaluate_conditions(pb, event)
    }
}

struct NoopEmailSenderFactory;

#[async_trait::async_trait]
impl EmailSenderFactoryTrait for NoopEmailSenderFactory {
    async fn build_smtp_sender(
        &self,
        _cfg: &SmtpConfig,
        _secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<Box<dyn EmailSenderTrait>>, Error> {
        Ok(None)
    }
}

struct NoopWebhookSender;

#[async_trait::async_trait]
impl WebhookSenderTrait for NoopWebhookSender {
    async fn post_json(&self, _url: &str, _timeout_secs: u64, _payload: &serde_json::Value) -> Result<u16, Error> {
        Ok(200)
    }
}

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

async fn test_db() -> Arc<Database> {
    Arc::new(Database::new(":memory:").await.expect("Failed to create test database"))
}

async fn test_engine(ac: Arc<dyn AccessControlPort>) -> SoarEngine {
    let db = test_db().await;
    db.seed_default_playbooks().await.ok();
    db.set_config_value("enforce_mode", "enforce").await.ok();
    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    SoarEngine::new(SoarEngineDeps {
        db: db as Arc<dyn SoarControlRepo>,
        config,
        access_control: ac,
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
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
        diagnostics: Vec::new(),
    };

    let action = PlaybookAction {
        action_order: 1,
        action_type: ActionType::BlockIp,
        params: PlaybookActionParams {
            ttl_secs: Some(600),
            ..Default::default()
        },
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
        diagnostics: Vec::new(),
    };

    let action = PlaybookAction {
        action_order: 1,
        action_type: ActionType::BlockIp,
        params: PlaybookActionParams {
            ttl_secs: Some(300),
            ..Default::default()
        },
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

    let expires = (Utc::now() + ChronoDuration::hours(1))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    db.commit_soar_block_to_db("192.168.1.100", IpVersion::V4, 1, &expires)
        .await
        .ok();

    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
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
    db.commit_soar_block_to_db("10.0.0.1", IpVersion::V4, 1, &expires)
        .await
        .ok();

    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
    })
    .await
    .expect("Failed to create engine");

    let result = engine.recover_active_blocks().await;
    assert!(result.is_ok(), "Recovery should succeed even when block_ip fails");

    assert!(mock.blocked_ips.lock().is_empty());
}

#[tokio::test]
async fn recover_pending_unblocks_removes_successful_retry() {
    let mock = Arc::new(MockAccessControl::new());
    let db = test_db().await;
    db.seed_default_playbooks().await.ok();
    db.insert_pending_unblock("10.0.0.2").await.expect("pending unblock");

    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db.clone() as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
    })
    .await
    .expect("Failed to create engine");

    engine.recover_active_blocks().await.expect("Recovery should succeed");

    {
        let unblocked = mock.unblocked_ips.lock();
        assert_eq!(unblocked.len(), 1);
        assert_eq!(unblocked[0], "10.0.0.2");
    }
    assert!(db.list_pending_unblocks().await.expect("pending unblocks").is_empty());
}

#[tokio::test]
async fn recover_pending_unblocks_increments_failed_retry() {
    let mock = Arc::new(MockAccessControl::new());
    mock.should_fail.store(true, Ordering::SeqCst);
    let db = test_db().await;
    db.seed_default_playbooks().await.ok();
    db.insert_pending_unblock("10.0.0.3").await.expect("pending unblock");

    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db.clone() as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
    })
    .await
    .expect("Failed to create engine");

    engine.recover_active_blocks().await.expect("Recovery should succeed");

    let pending = db.list_pending_unblocks().await.expect("pending unblocks");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_ip, "10.0.0.3");
    assert_eq!(pending[0].retry_count, 1);
}

#[tokio::test]
async fn exhausted_pending_unblock_remains_durable_but_is_not_retried() {
    let mock = Arc::new(MockAccessControl::new());
    let db = test_db().await;
    db.insert_pending_unblock("10.0.0.4").await.expect("pending unblock");

    let cache = Arc::new(AtomicU8::new(2));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let mut cfg = load_app_config(&*db).await.expect("load config");
    cfg.soar.max_pending_unblock_retries = 0;
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db.clone() as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
    })
    .await
    .expect("Failed to create engine");

    engine.recover_active_blocks().await.expect("Recovery should succeed");
    engine
        .recover_active_blocks()
        .await
        .expect("Second recovery should succeed");

    let pending = db.list_pending_unblocks().await.expect("pending unblocks");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_ip, "10.0.0.4");
    assert_eq!(pending[0].retry_count, 0);
    assert!(pending[0].exhausted_at.is_some());
    assert_eq!(pending[0].last_error.as_deref(), Some("max retries exceeded"));
    assert!(
        mock.unblocked_ips.lock().is_empty(),
        "exhausted pending unblock must not be retried automatically"
    );
}

#[tokio::test]
async fn block_ip_respects_cap() {
    let mock = Arc::new(MockAccessControl::new());
    let engine = test_engine(mock.clone()).await;

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
        diagnostics: Vec::new(),
    };

    let action = PlaybookAction {
        action_order: 1,
        action_type: ActionType::BlockIp,
        params: PlaybookActionParams {
            ttl_secs: Some(600),
            ..Default::default()
        },
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
        diagnostics: Vec::new(),
    };

    let playbooks = engine.find_matching_playbooks(&event);
    assert!(!playbooks.is_empty(), "Should have matching playbooks");

    let pb = &playbooks[0];

    let result = engine.execute_playbook(pb, &event).await;
    assert!(result.is_ok());
    assert!(!mock.blocked_ips.lock().is_empty());

    let blocked_before = mock.blocked_ips.lock().len();
    let result = engine.execute_playbook(pb, &event).await;
    assert!(result.is_ok());
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
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock.clone(),
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
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
        diagnostics: Vec::new(),
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

    assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

    engine.decrement_block_count();
    assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

    engine.matcher.active_block_count.store(2, Ordering::SeqCst);
    engine.decrement_block_count();
    assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 1);
    engine.decrement_block_count();
    assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);

    engine.decrement_block_count();
    assert_eq!(engine.matcher.active_block_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reload_cache_loads_playbooks_via_join() {
    let mock = Arc::new(MockAccessControl::new());
    let db = test_db().await;
    db.seed_default_playbooks().await.ok();

    let cache = Arc::new(AtomicU8::new(0));
    seed_config_defaults(&*db).await.expect("seed config defaults");
    let cfg = load_app_config(&*db).await.expect("load config");
    let config = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = SoarEngine::new(SoarEngineDeps {
        db: db.clone() as Arc<dyn SoarControlRepo>,
        config,
        access_control: mock,
        alert_notifier: None,
        geoip: None,
        rate_limit: None,
        enforce_level_cache: cache,
        secrets: None,
        email_sender_factory: Arc::new(NoopEmailSenderFactory),
        webhook_sender: Arc::new(NoopWebhookSender),
    })
    .await
    .expect("Failed to create engine");

    let count = engine.matcher.playbooks.load().len();
    assert!(count > 0, "Should have loaded default playbooks");

    let input = CreatePlaybookInput {
        name: "test_pb".to_string(),
        trigger_event: "port_scan".to_string(),
        condition_threshold: None,
        condition_count: None,
        condition_window_secs: None,
        cooldown_secs: 60,
        actions: Vec::new(),
        conditions: Vec::new(),
    };
    let actions = [ActionInput {
        action_order: 1,
        action_type: "log".to_string(),
        params_json: "{}".to_string(),
    }];
    db.insert_playbook_atomic(&input, &actions, &[])
        .await
        .expect("insert playbook");

    assert_eq!(engine.matcher.playbooks.load().len(), count);

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
        diagnostics: Vec::new(),
    }
}

fn make_playbook(conditions: Vec<PlaybookCondition>) -> Playbook {
    Playbook {
        id: 999,
        name: "test-playbook".to_string(),
        trigger_event: CanonicalAttackType::Unknown,
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
async fn fallback_does_not_record_cooldown_when_block_fails() {
    let mock = Arc::new(MockAccessControl::new());
    mock.should_fail.store(true, Ordering::SeqCst);
    let engine = test_engine(mock.clone()).await;
    let event = test_event(0.95, None, "1.2.3.4", false);

    engine
        .execute_fallback(&event)
        .await
        .expect("fallback should persist execution");

    assert!(
        !engine.is_cooldown_active(-1, &event.source_ip, 60),
        "failed fallback block must not suppress a later retry"
    );

    mock.should_fail.store(false, Ordering::SeqCst);
    engine
        .execute_fallback(&event)
        .await
        .expect("retry should run after failure");

    assert_eq!(mock.blocked_ips.lock().as_slice(), &[event.source_ip]);
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
    assert!(engine.evaluate_conditions(&pb, &test_event(0.95, Some("CN"), "1.2.3.4", false)));
    assert!(!engine.evaluate_conditions(&pb, &test_event(0.95, Some("US"), "1.2.3.4", false)));
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
    assert!(!engine.evaluate_conditions(&pb, &event));
    assert!(!engine.evaluate_conditions(&pb, &event));
    assert!(engine.evaluate_conditions(&pb, &event));
}
