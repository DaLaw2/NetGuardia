use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use macros::log;
use serde_json::Value;
use tokio::sync::Semaphore;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::core::soar::frequency::FrequencyTracker;
use crate::core::soar::rate_limit_owner::RateLimitOwnerHandle;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::notification::AlertNotifier;
use crate::interface::port::rate_limit_api::RateLimitPort;
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::config::constants::MAX_PENDING_UNBLOCK_RETRIES;
use crate::model::detection::attack_type::canonical_from_str;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::soar::SoarLog;
use crate::model::soar::condition::{ConditionType, PlaybookCondition};
use crate::model::soar::playbook::{Playbook, PlaybookAction};

/// Cooldown key: (playbook_id, source_ip)
type CooldownKey = (i64, String);

/// Maximum number of `handle_threat_event` futures allowed in flight at the
/// same time. Replaces the previous unbounded `tokio::spawn`-per-event
/// pattern, which under fusion-emit bursts could pile up faster than the
/// executor drains and starve other async work. When all permits are held,
/// the event loop blocks at `Semaphore::acquire_owned` — backpressure then
/// surfaces as broadcast `Lagged` (visible in the receiver-lag metric)
/// rather than as silent task-queue growth.
const SOAR_HANDLE_CONCURRENCY: usize = 16;

/// SOAR Engine — subscribes to ThreatDetectedEvent and executes matching playbooks.
///
/// The engine is intentionally split across three files within `core::soar`:
/// - `engine.rs` (this file) — struct definition, lifecycle (new/start/event_loop),
///   cache reload, recovery, rate-limit-TTL restoration
/// - `matcher.rs` — domain: playbook matching, condition evaluation, cooldowns
/// - `actions.rs` — application: action dispatch + all action_* implementations
///
/// Fields are `pub(super)` so the sibling files can read them; external
/// callers still see the struct via its public methods only.
pub struct SoarEngine {
    pub(super) db: Arc<dyn AppRepo>,
    pub(super) access_control: Arc<dyn AccessControlPort>,
    /// In-memory cache of playbooks (loaded at startup, refreshed on change).
    pub(super) playbooks: ArcSwap<Vec<Arc<Playbook>>>,
    /// In-memory cache of admin whitelist IPs.
    pub(super) admin_whitelist: ArcSwap<HashSet<String>>,
    /// Cooldown tracker: maps (playbook_id, source_ip) → last execution time.
    pub(super) cooldowns: DashMap<CooldownKey, Instant>,
    /// Frequency tracker for frequency-based conditions.
    pub(super) frequency_tracker: FrequencyTracker,
    /// AtomicU32 counter for active auto-blocks (avoids DB query per event).
    pub(super) active_block_count: AtomicU32,
    /// Optional alert notifier (Telegram, etc.).
    pub(super) alert_notifier: Option<Arc<dyn AlertNotifier>>,
    /// Optional GeoIP service for country lookups.
    pub(super) geoip: Option<Arc<GeoIpService>>,
    /// Owner-task handle that serializes the rate-limit DB+eBPF
    /// read-modify-write batch. `None` when no `RateLimitPort` was wired
    /// up (eBPF unavailable); SOAR actions that need rate-limit then
    /// fail with `SoarError::RateLimitUnavailable`.
    pub(super) rate_limit: Option<RateLimitOwnerHandle>,
    /// Cached enforce level: Monitor=0, MlOnly=1, Enforce=2.
    pub(super) enforce_level_cache: Arc<AtomicU8>,
    /// Secret store for decrypting SMTP passwords etc.
    pub(super) secrets: Option<Arc<dyn SecretStorePort>>,
}

impl SoarEngine {
    pub fn new(
        db: Arc<dyn AppRepo>,
        access_control: Arc<dyn AccessControlPort>,
        alert_notifier: Option<Arc<dyn AlertNotifier>>,
        geoip: Option<Arc<GeoIpService>>,
        rate_limit: Option<Arc<dyn RateLimitPort>>,
        enforce_level_cache: Arc<AtomicU8>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Result<Self, Error> {
        let rate_limit_owner = rate_limit.map(|rl| RateLimitOwnerHandle::spawn(db.clone(), rl));
        let engine = Self {
            db,
            access_control,
            playbooks: ArcSwap::from_pointee(Vec::new()),
            admin_whitelist: ArcSwap::from_pointee(HashSet::new()),
            cooldowns: DashMap::new(),
            frequency_tracker: FrequencyTracker::new(),
            active_block_count: AtomicU32::new(0),
            alert_notifier,
            geoip,
            rate_limit: rate_limit_owner,
            enforce_level_cache,
            secrets,
        };
        engine.reload_cache()?;
        Ok(engine)
    }

    /// Load playbooks and admin whitelist from DB into memory.
    pub fn reload_cache(&self) -> Result<(), Error> {
        // Load playbooks via single JOIN query (no N+1)
        let rows = self.db.load_playbooks_with_actions()?;
        let mut playbooks: Vec<Playbook> = Vec::new();

        for (
            pb_id,
            name,
            enabled,
            trigger_event,
            threshold,
            _count,
            _window,
            cooldown,
            _action_id,
            action_order,
            action_type,
            action_params,
        ) in rows
        {
            // Check if this row belongs to the same playbook as the last one
            let needs_new = playbooks.last().is_none_or(|last| last.id != pb_id);
            if needs_new {
                let _ = threshold; // persisted for schema stability; runtime gating comes from the Condition rows
                playbooks.push(Playbook {
                    id: pb_id,
                    name,
                    enabled,
                    trigger_event,
                    cooldown_secs: cooldown,
                    actions: Vec::new(),
                    conditions: Vec::new(),
                });
            }
            // Safe: we just pushed if empty, and last() was Some otherwise
            let Some(pb) = playbooks.last_mut() else {
                continue;
            };

            if let (Some(order), Some(atype), Some(params_str)) = (action_order, action_type, action_params) {
                pb.actions.push(PlaybookAction {
                    action_order: order,
                    action_type: atype,
                    params: serde_json::from_str(&params_str).unwrap_or_else(|e| {
                        log!(SoarLog::PlaybookError(
                            pb.name.clone(),
                            format!("Malformed action params JSON: {e}"),
                        ));
                        Value::Object(Default::default())
                    }),
                });
            }
        }

        // Load conditions and attach to playbooks
        let condition_rows = self.db.load_all_playbook_conditions()?;
        for (_cid, pb_id, ctype_str, operator, value, value2) in condition_rows {
            if let Ok(ctype) = ctype_str.parse::<ConditionType>()
                && let Some(pb) = playbooks.iter_mut().find(|p| p.id == pb_id)
            {
                // Validate operator at load time to prevent silent fallback to defaults
                let valid = match ctype {
                    ConditionType::Threshold => matches!(operator.as_str(), ">=" | "<="),
                    ConditionType::SourceCountry | ConditionType::IpPattern => {
                        matches!(operator.as_str(), "in" | "not_in")
                    }
                    ConditionType::RepeatOffender => operator == "==",
                    ConditionType::Frequency => operator == ">=",
                    ConditionType::MultiSourceMin => operator == ">=",
                    ConditionType::SingleSourceHigh => operator == ">=",
                    ConditionType::FusedConfidenceAbove => matches!(operator.as_str(), ">=" | "<="),
                };
                if !valid {
                    log!(SoarLog::InvalidConditionOperator(
                        pb.name.clone(),
                        ctype_str.clone(),
                        operator.clone(),
                    ));
                    continue;
                }
                pb.conditions.push(PlaybookCondition {
                    condition_type: ctype,
                    operator,
                    value,
                    value2,
                });
            }
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
        self.playbooks.store(Arc::new(playbooks));

        // Load admin whitelist
        let whitelist = self.db.load_admin_whitelist()?;
        let whitelist: HashSet<String> = whitelist.into_iter().collect();
        let whitelist_count = whitelist.len();
        self.admin_whitelist.store(Arc::new(whitelist));

        // Initialize block counter from DB
        let count = self.db.count_active_soar_blocks()?;
        self.active_block_count.store(count, Ordering::SeqCst);

        log!(SoarLog::CacheLoaded(playbook_count, whitelist_count, count));

        Ok(())
    }

    /// Subscribe to ThreatDetectedEvent and start processing.
    /// Returns an error if subscription fails — caller must handle this as a critical failure.
    pub fn start(self: Arc<Self>, comm: Arc<CommunicationManager>) -> Result<(), Error> {
        let rx = comm.subscribe_event::<ThreatDetectedEvent>().map_err(|e| {
            log!(SoarLog::EventHandlingFailed(format!(
                "CRITICAL: SOAR engine failed to subscribe — automated threat response is DISABLED: {}",
                e
            )));
            SoarError::ActionFailed("subscribe", e)
        })?;
        tokio::spawn(async move {
            Self::event_loop(self, rx).await;
        });
        Ok(())
    }

    async fn event_loop(self: Arc<Self>, mut rx: broadcast::Receiver<ThreatDetectedEvent>) {
        log!(SoarLog::EngineStarted);
        let semaphore = Arc::new(Semaphore::new(SOAR_HANDLE_CONCURRENCY));
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Bounded fan-out: hold one permit per in-flight handler.
                    // When SOAR_HANDLE_CONCURRENCY are already running, this
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

        let active_blocks = self.db.get_active_soar_blocks()?;
        let count = active_blocks.len();

        for (_id, source_ip, _playbook_id, _expires_at) in &active_blocks {
            // Preserve original error-swallowing behavior during recovery
            if let Err(e) = self.access_control.block_ip(source_ip) {
                log!(SoarLog::RecoveryFailed(source_ip.clone(), e.to_string()));
            }
        }

        if count > 0 {
            log!(SoarLog::RecoveryComplete(count));
        }

        Ok(())
    }

    /// Retry pending unblocks that failed during previous runs.
    async fn retry_pending_unblocks(&self) {
        let pending = match self.db.load_pending_unblocks() {
            Ok(p) => p,
            Err(e) => {
                log!(SoarLog::EventHandlingFailed(format!(
                    "Failed to load pending unblocks: {}",
                    e
                )));
                return;
            }
        };

        for (id, source_ip, retry_count) in pending {
            if retry_count >= MAX_PENDING_UNBLOCK_RETRIES {
                log!(SoarLog::EventHandlingFailed(format!(
                    "Giving up on pending unblock for IP {} after {} retries",
                    source_ip, retry_count
                )));
                // Remove from queue to avoid infinite retries
                let _ = self.db.delete_pending_unblock(id);
                continue;
            }

            match self.access_control.unblock_ip(&source_ip) {
                Ok(()) => {
                    let _ = self.db.delete_pending_unblock(id);
                    log!(SoarLog::EventHandlingFailed(format!(
                        "Successfully unblocked orphan IP {} on retry #{}",
                        source_ip,
                        retry_count + 1
                    )));
                }
                Err(e) => {
                    let _ = self.db.increment_pending_unblock_retry(id);
                    log!(SoarLog::EventHandlingFailed(format!(
                        "Retry #{} failed to unblock orphan IP {}: {}",
                        retry_count + 1,
                        source_ip,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::error::ebpf::EbpfError;
    use crate::model::event::DetectionSource;
    use chrono::{Duration as ChronoDuration, Utc};
    use parking_lot::Mutex;
    use std::sync::atomic::AtomicBool;

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

    fn test_db() -> Arc<crate::adapter::persistence::Database> {
        use crate::adapter::persistence::Database;
        Arc::new(Database::new(":memory:").expect("Failed to create test database"))
    }

    fn test_engine(ac: Arc<dyn AccessControlPort>) -> SoarEngine {
        let db = test_db();
        db.seed_default_playbooks().ok();
        // Tests expect enforce mode to be active so block_ip actions execute
        db.set_setting("enforce_mode", "enforce").ok();
        // enforce=2
        let cache = Arc::new(AtomicU8::new(2));
        SoarEngine::new(db as Arc<dyn AppRepo>, ac, None, None, None, cache, None)
            .expect("Failed to create SOAR engine")
    }

    #[tokio::test]
    async fn block_ip_calls_access_control_port() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock.clone());

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
        let engine = test_engine(mock.clone());

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
        let db = test_db();
        db.seed_default_playbooks().ok();

        // Insert a fake active block
        let expires = (Utc::now() + ChronoDuration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.insert_soar_block_rule("192.168.1.100", 1, &expires).ok();

        let cache = Arc::new(AtomicU8::new(2));
        let engine = SoarEngine::new(db as Arc<dyn AppRepo>, mock.clone(), None, None, None, cache, None)
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
        let db = test_db();
        db.seed_default_playbooks().ok();

        let expires = (Utc::now() + ChronoDuration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.insert_soar_block_rule("10.0.0.1", 1, &expires).ok();

        let cache = Arc::new(AtomicU8::new(2));
        let engine = SoarEngine::new(db as Arc<dyn AppRepo>, mock.clone(), None, None, None, cache, None)
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
        let engine = test_engine(mock.clone());

        // Set counter to max (default cap is 100)
        engine.active_block_count.store(100, Ordering::SeqCst);

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
        let engine = test_engine(mock.clone());

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
        let db = test_db();
        db.seed_default_playbooks().ok();
        db.insert_admin_whitelist("1.2.3.4").ok();

        let cache = Arc::new(AtomicU8::new(2));
        let engine = SoarEngine::new(db as Arc<dyn AppRepo>, mock.clone(), None, None, None, cache, None)
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

    #[test]
    fn decrement_block_count_no_underflow() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);

        // Start at 0
        assert_eq!(engine.active_block_count.load(Ordering::SeqCst), 0);

        // Decrement should not underflow
        engine.decrement_block_count();
        assert_eq!(engine.active_block_count.load(Ordering::SeqCst), 0);

        // Set to 2, decrement twice → should be 0
        engine.active_block_count.store(2, Ordering::SeqCst);
        engine.decrement_block_count();
        assert_eq!(engine.active_block_count.load(Ordering::SeqCst), 1);
        engine.decrement_block_count();
        assert_eq!(engine.active_block_count.load(Ordering::SeqCst), 0);

        // One more decrement should stay at 0
        engine.decrement_block_count();
        assert_eq!(engine.active_block_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn reload_cache_loads_playbooks_via_join() {
        let mock = Arc::new(MockAccessControl::new());
        let db = test_db();
        db.seed_default_playbooks().ok();

        let cache = Arc::new(AtomicU8::new(0));
        let engine = SoarEngine::new(db.clone() as Arc<dyn AppRepo>, mock, None, None, None, cache, None)
            .expect("Failed to create engine");

        // Should have loaded default playbooks
        let count = engine.playbooks.load().len();
        assert!(count > 0, "Should have loaded default playbooks");

        // Add a new playbook directly to DB
        db.insert_playbook("test_pb", "port_scan", None, None, None, 60).ok();

        // Cache should not have it yet
        assert_eq!(engine.playbooks.load().len(), count);

        // After reload, should have one more
        engine.reload_cache().expect("reload should succeed");
        assert_eq!(engine.playbooks.load().len(), count + 1);
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

    #[test]
    fn condition_threshold_gte_passes() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: ">=".to_string(),
            value: "0.9".to_string(),
            value2: None,
        }]);
        let event = test_event(0.95, None, "1.2.3.4", false);
        assert!(engine.evaluate_conditions(&pb, &event));
    }

    #[test]
    fn condition_threshold_gte_fails() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: ">=".to_string(),
            value: "0.9".to_string(),
            value2: None,
        }]);
        let event = test_event(0.85, None, "1.2.3.4", false);
        assert!(!engine.evaluate_conditions(&pb, &event));
    }

    #[test]
    fn condition_threshold_lte() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::Threshold,
            operator: "<=".to_string(),
            value: "0.5".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.3, None, "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.7, None, "1.2.3.4", false)));
    }

    #[test]
    fn condition_source_country_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
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

    #[test]
    fn condition_source_country_not_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::SourceCountry,
            operator: "not_in".to_string(),
            value: "US, TW".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, Some("CN"), "1.2.3.4", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, Some("TW"), "1.2.3.4", false)));
    }

    #[test]
    fn condition_ip_pattern_in() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::IpPattern,
            operator: "in".to_string(),
            value: "10.0.0.0/8".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, None, "10.1.2.3", false)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, None, "192.168.1.1", false)));
    }

    #[test]
    fn condition_repeat_offender() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
        let pb = make_playbook(vec![PlaybookCondition {
            condition_type: ConditionType::RepeatOffender,
            operator: "==".to_string(),
            value: "true".to_string(),
            value2: None,
        }]);
        assert!(engine.evaluate_conditions(&pb, &test_event(0.9, None, "1.2.3.4", true)));
        assert!(!engine.evaluate_conditions(&pb, &test_event(0.9, None, "1.2.3.4", false)));
    }

    #[test]
    fn condition_and_logic_all_must_pass() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
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

    #[test]
    fn frequency_condition_counts_events() {
        let mock = Arc::new(MockAccessControl::new());
        let engine = test_engine(mock);
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
