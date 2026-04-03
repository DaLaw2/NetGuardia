use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use dashmap::DashMap;
use macros::log;
use tokio::sync::broadcast;

use crate::core::ebpf::rate_limit::RateLimitConfig;
use crate::core::soar::frequency::FrequencyTracker;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::notification::{AlertNotifier, AlertPayload};
use crate::interface::port::secret_store::SecretStorePort;
use crate::interface::port::soar::SoarPort;
use crate::model::config::constants::MAX_PENDING_UNBLOCK_RETRIES;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::soar::SoarLog;
use crate::model::soar::condition::{ConditionType, PlaybookCondition};
use crate::model::soar::playbook::{Playbook, PlaybookAction};

/// Cooldown key: (playbook_id, source_ip)
type CooldownKey = (i64, String);

/// SOAR Engine — subscribes to ThreatDetectedEvent and executes matching playbooks.
pub struct SoarEngine {
    db: Arc<dyn SoarPort>,
    access_control: Arc<dyn AccessControlPort>,
    /// In-memory cache of playbooks (loaded at startup, refreshed on change).
    playbooks: parking_lot::RwLock<Vec<Playbook>>,
    /// In-memory cache of admin whitelist IPs.
    admin_whitelist: parking_lot::RwLock<HashSet<String>>,
    /// Cooldown tracker: maps (playbook_id, source_ip) → last execution time.
    cooldowns: DashMap<CooldownKey, std::time::Instant>,
    /// Frequency tracker for frequency-based conditions.
    frequency_tracker: FrequencyTracker,
    /// AtomicU32 counter for active auto-blocks (avoids DB query per event).
    active_block_count: AtomicU32,
    /// Optional alert notifier (Telegram, etc.).
    alert_notifier: Option<Arc<dyn AlertNotifier>>,
    /// Optional GeoIP service for country lookups.
    geoip: Option<Arc<GeoIpService>>,
    /// Optional rate limit config for adjust_rate_limit action.
    rate_limit: Option<Arc<RateLimitConfig>>,
    /// Lock to serialize rate limit read-save-write sequences (Item 6: atomicity).
    rate_limit_lock: tokio::sync::Mutex<()>,
    /// Cached enforce level: Monitor=0, MlOnly=1, Enforce=2.
    enforce_level_cache: Arc<AtomicU8>,
    /// Secret store for decrypting SMTP passwords etc.
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl SoarEngine {
    pub fn new(
        db: Arc<dyn SoarPort>,
        access_control: Arc<dyn AccessControlPort>,
        alert_notifier: Option<Arc<dyn AlertNotifier>>,
        geoip: Option<Arc<GeoIpService>>,
        rate_limit: Option<Arc<RateLimitConfig>>,
        enforce_level_cache: Arc<AtomicU8>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Result<Self, Error> {
        let engine = Self {
            db,
            access_control,
            playbooks: parking_lot::RwLock::new(Vec::new()),
            admin_whitelist: parking_lot::RwLock::new(HashSet::new()),
            cooldowns: DashMap::new(),
            frequency_tracker: FrequencyTracker::new(),
            active_block_count: AtomicU32::new(0),
            alert_notifier,
            geoip,
            rate_limit,
            rate_limit_lock: tokio::sync::Mutex::new(()),
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
                playbooks.push(Playbook {
                    id: pb_id,
                    name,
                    enabled,
                    trigger_event,
                    condition_threshold: threshold,
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
                        log!(SoarLog::PlaybookError {
                            name: pb.name.clone(),
                            error: format!("Malformed action params JSON: {}", e),
                        });
                        serde_json::Value::Object(Default::default())
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

        *self.playbooks.write() = playbooks;

        // Load admin whitelist
        let whitelist = self.db.load_admin_whitelist()?;
        *self.admin_whitelist.write() = whitelist.into_iter().collect();

        // Initialize block counter from DB
        let count = self.db.count_active_soar_blocks()?;
        self.active_block_count.store(count, Ordering::SeqCst);

        log!(SoarLog::CacheLoaded(
            self.playbooks.read().len(),
            self.admin_whitelist.read().len(),
            count,
        ));

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
            SoarError::ActionFailed {
                action_type: "subscribe".to_string(),
                reason: e.to_string(),
            }
        })?;
        tokio::spawn(async move {
            Self::event_loop(self, rx).await;
        });
        Ok(())
    }

    async fn event_loop(self: Arc<Self>, mut rx: broadcast::Receiver<ThreatDetectedEvent>) {
        log!(SoarLog::EngineStarted);
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let engine = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = engine.handle_threat_event(&event).await {
                            log!(SoarLog::EventHandlingFailed(e.to_string()));
                        }
                    });
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    log!(SoarLog::ReceiverLagged(n));
                }
                Err(broadcast::error::RecvError::Closed) => {
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

    /// Find playbooks matching the event via trigger_event + multi-condition AND logic.
    fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Playbook> {
        let playbooks = self.playbooks.read();
        playbooks
            .iter()
            .filter(|pb| pb.enabled && pb.trigger_event == event.attack_type)
            .filter(|pb| self.evaluate_conditions(pb, event))
            .cloned()
            .collect()
    }

    /// Evaluate all conditions on a playbook (AND logic).
    /// If conditions vec is empty, falls back to legacy `condition_threshold` check.
    fn evaluate_conditions(&self, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        if pb.conditions.is_empty() {
            // Legacy: use inline threshold if present
            if let Some(threshold) = pb.condition_threshold {
                return (event.confidence as f64) >= threshold;
            }
            return true;
        }

        // Evaluate non-frequency conditions first (avoid recording non-matching events)
        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency {
                continue;
            }
            if !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        // Evaluate frequency conditions last
        for cond in &pb.conditions {
            if cond.condition_type == ConditionType::Frequency && !self.evaluate_single_condition(cond, pb, event) {
                return false;
            }
        }

        true
    }

    /// Evaluate a single condition against the event.
    /// The `operator` field controls comparison direction:
    /// - Threshold: ">=" (default) or "<="
    /// - SourceCountry/IpPattern: "in" (default) or "not_in"
    /// - RepeatOffender: "==" only
    /// - Frequency: ">=" only
    fn evaluate_single_condition(&self, cond: &PlaybookCondition, pb: &Playbook, event: &ThreatDetectedEvent) -> bool {
        match cond.condition_type {
            ConditionType::Threshold => {
                let threshold = match cond.value.parse::<f64>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let confidence = event.confidence as f64;
                let met = if cond.operator == "<=" {
                    confidence <= threshold
                } else {
                    confidence >= threshold
                };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "threshold".to_string(),
                        pb.name.clone(),
                        format!("{:.2}", event.confidence),
                    ));
                }
                met
            }
            ConditionType::SourceCountry => {
                let countries: Vec<&str> = cond.value.split(',').map(|s| s.trim()).collect();
                let matches = event
                    .geoip_country
                    .as_ref()
                    .is_some_and(|c| countries.iter().any(|&cc| cc.eq_ignore_ascii_case(c)));
                let met = if cond.operator == "not_in" { !matches } else { matches };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "source_country".to_string(),
                        pb.name.clone(),
                        event.geoip_country.clone().unwrap_or_else(|| "none".to_string()),
                    ));
                }
                met
            }
            ConditionType::IpPattern => {
                let net = match cond.value.parse::<ipnetwork::IpNetwork>() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                let ip = match event.source_ip.parse::<IpAddr>() {
                    Ok(a) => a,
                    Err(_) => return false,
                };
                let matches = net.contains(ip);
                let met = if cond.operator == "not_in" { !matches } else { matches };
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "ip_pattern".to_string(),
                        pb.name.clone(),
                        event.source_ip.clone(),
                    ));
                }
                met
            }
            ConditionType::RepeatOffender => {
                let expected = cond.value.eq_ignore_ascii_case("true");
                let met = event.is_repeat_offender == expected;
                if !met {
                    log!(SoarLog::ConditionNotMet(
                        "repeat_offender".to_string(),
                        pb.name.clone(),
                        format!("{}", event.is_repeat_offender),
                    ));
                }
                met
            }
            ConditionType::Frequency => {
                let required = match cond.value.parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                let window_secs = cond.value2.as_ref().and_then(|s| s.parse::<u64>().ok()).unwrap_or(60);
                let count = self
                    .frequency_tracker
                    .record_and_count(pb.id, &event.source_ip, window_secs);
                let met = count >= required;
                if !met {
                    log!(SoarLog::FrequencyNotMet(pb.name.clone(), count, required, window_secs));
                }
                met
            }
        }
    }

    /// Check if cooldown is active for this playbook + source IP combination.
    fn is_cooldown_active(&self, playbook_id: i64, source_ip: &str, cooldown_secs: i64) -> bool {
        let key = (playbook_id, source_ip.to_string());
        if let Some(last_exec) = self.cooldowns.get(&key) {
            let elapsed = last_exec.elapsed();
            if elapsed.as_secs() < cooldown_secs as u64 {
                return true;
            }
        }
        false
    }

    /// Record cooldown for a playbook + source IP combination.
    fn record_cooldown(&self, playbook_id: i64, source_ip: &str) {
        let key = (playbook_id, source_ip.to_string());
        self.cooldowns.insert(key, std::time::Instant::now());
    }

    /// Execute a single playbook against an event.
    async fn execute_playbook(&self, playbook: &Playbook, event: &ThreatDetectedEvent) -> Result<(), Error> {
        // Check cooldown
        if self.is_cooldown_active(playbook.id, &event.source_ip, playbook.cooldown_secs) {
            log!(SoarLog::CooldownActive(playbook.name.clone(), event.source_ip.clone()));
            return Ok(());
        }

        // Check admin whitelist
        if self.admin_whitelist.read().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                playbook.name.clone()
            ));
            return Ok(());
        }

        // Execute actions in order
        let mut action_results = Vec::new();
        for action in &playbook.actions {
            let result = self.execute_action(action, event, playbook.id).await;
            let result_json = match &result {
                Ok(msg) => serde_json::json!({"action": &action.action_type, "status": "ok", "message": msg}),
                Err(e) => {
                    serde_json::json!({"action": &action.action_type, "status": "error", "message": e.to_string()})
                }
            };
            action_results.push(result_json);
            if let Err(e) = result {
                log!(SoarLog::PlaybookError(
                    playbook.name.clone(),
                    format!("Action '{}': {}", action.action_type, e)
                ));
            }
        }

        // Record cooldown
        self.record_cooldown(playbook.id, &event.source_ip);

        // Write audit trail
        let actions_json = serde_json::to_string(&action_results).unwrap_or_default();
        self.db
            .insert_soar_execution(playbook.id, Some(&event.source_ip), &event.attack_type, &actions_json)?;

        log!(SoarLog::PlaybookExecuted(
            playbook.name.clone(),
            event.source_ip.clone(),
            event.attack_type.clone()
        ));

        Ok(())
    }

    /// Check if the system is in enforce mode (as opposed to monitor mode).
    /// Reads from the in-memory AtomicU8 cache: Monitor=0, MlOnly=1, Enforce=2.
    fn is_enforce_mode(&self) -> bool {
        self.enforce_level_cache.load(Ordering::Relaxed) == 2
    }

    /// Execute a single action.
    async fn execute_action(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        match action.action_type.as_str() {
            "block_ip" => {
                if !self.is_enforce_mode() {
                    log!(SoarLog::MonitorModeSkipped(
                        action.action_type.clone(),
                        event.source_ip.clone()
                    ));
                    return Ok(format!("[monitor] Would block IP {} — skipped", event.source_ip));
                }
                self.action_block_ip(action, event, playbook_id).await
            }
            "adjust_rate_limit" => {
                if !self.is_enforce_mode() {
                    log!(SoarLog::MonitorModeSkipped(
                        action.action_type.clone(),
                        event.source_ip.clone()
                    ));
                    return Ok("[monitor] Would adjust rate limit — skipped".to_string());
                }
                self.action_adjust_rate_limit(action, event).await
            }
            "send_telegram" => self.action_send_telegram(event).await,
            "send_email" => self.action_send_email(event).await,
            "webhook" => self.action_webhook(action, event).await,
            "log" => self.action_log(action, event),
            other => Err(SoarError::ActionFailed {
                action_type: other.to_string(),
                reason: "Unknown action type".to_string(),
            }
            .into()),
        }
    }

    /// Block an IP via eBPF ACL with TTL.
    async fn action_block_ip(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        let ttl_secs = action.params.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(1800);

        // Validate TTL (runtime-configurable via DB)
        let max_ttl: u64 = self
            .db
            .get_setting("soar_max_ttl_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400);
        if ttl_secs > max_ttl {
            return Err(SoarError::InvalidTtl {
                ttl_secs,
                max_secs: max_ttl,
            }
            .into());
        }

        // Atomically check cap and reserve a slot using CAS loop (runtime-configurable via DB)
        let max_cap: u32 = self
            .db
            .get_setting("soar_max_auto_block_cap")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        loop {
            let current_count = self.active_block_count.load(Ordering::SeqCst);
            if current_count >= max_cap {
                log!(SoarLog::CapReached(current_count, max_cap, event.source_ip.clone()));
                return Err(SoarError::CapReached { max_cap }.into());
            }
            if self
                .active_block_count
                .compare_exchange(current_count, current_count + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }

        // Block IP via AccessControlPort (handles IPv4/IPv6 dispatch internally)
        if let Err(e) = self.access_control.block_ip(&event.source_ip).await {
            self.decrement_block_count();
            return Err(e);
        }

        // Calculate expiry time
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

        // Record in soar_block_rules
        if let Err(e) = self
            .db
            .insert_soar_block_rule(&event.source_ip, playbook_id, &expires_str)
        {
            // Attempt to roll back the eBPF block — on failure, queue for retry
            if let Err(unblock_err) = self.access_control.unblock_ip(&event.source_ip).await {
                log!(SoarLog::EventHandlingFailed(format!(
                    "CRITICAL: Failed to unblock IP {} after DB error — queueing for retry: {}",
                    event.source_ip, unblock_err
                )));
                // Write to pending_unblock table so recovery can retry later
                if let Err(pend_err) = self.db.insert_pending_unblock(&event.source_ip) {
                    log!(SoarLog::EventHandlingFailed(format!(
                        "CRITICAL: Failed to queue pending unblock for IP {}: {}",
                        event.source_ip, pend_err
                    )));
                }
            }
            self.decrement_block_count();
            return Err(e);
        }

        // Also persist to acl_rules for consistency
        let ip_version = crate::core::playbook_service::ip_version_from_str(&event.source_ip);
        self.db
            .insert_acl_rule(ip_version, "source", "blacklist", &event.source_ip, 0)?;

        Ok(format!("Blocked IP {} for {}s", event.source_ip, ttl_secs))
    }

    /// Temporarily reduce global rate limits by a factor with TTL-based restoration.
    /// Params: { "factor": 0.5, "ttl_secs": 600 }
    /// factor < 1.0 means stricter (e.g. 0.5 = half the current rate).
    async fn action_adjust_rate_limit(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
    ) -> Result<String, Error> {
        let rate_limit = self.rate_limit.as_ref().ok_or_else(|| SoarError::ActionFailed {
            action_type: "adjust_rate_limit".to_string(),
            reason: "Rate limit config not available".to_string(),
        })?;

        let factor = action.params.get("factor").and_then(|v| v.as_f64()).unwrap_or(0.5);
        let ttl_secs = action.params.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(600);

        if !(0.01..=1.0).contains(&factor) {
            return Err(SoarError::ActionFailed {
                action_type: "adjust_rate_limit".to_string(),
                reason: format!("factor must be 0.01..1.0, got {}", factor),
            }
            .into());
        }

        let max_ttl: u64 = self
            .db
            .get_setting("soar_max_ttl_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400);
        if ttl_secs > max_ttl {
            return Err(SoarError::InvalidTtl {
                ttl_secs,
                max_secs: max_ttl,
            }
            .into());
        }

        // Acquire lock to serialize rate limit read-save-write (Item 6: atomicity)
        let _guard = self.rate_limit_lock.lock().await;

        // Read current rates, save originals, apply reduced rates
        let current_packet = rate_limit.get_packet_rate().unwrap_or(10000);
        let current_syn = rate_limit.get_syn_rate().unwrap_or(1000);
        let current_udp = rate_limit.get_udp_rate().unwrap_or(5000);
        let current_dns = rate_limit.get_dns_rate().unwrap_or(2000);

        // Store original rates for restoration (only if not already adjusted)
        let key = "soar_rate_limit_original";
        if self.db.get_setting(key)?.filter(|s| !s.is_empty()).is_none() {
            let original = serde_json::json!({
                "packet_rate": current_packet,
                "syn_rate": current_syn,
                "udp_rate": current_udp,
                "dns_rate": current_dns,
            });
            self.db.set_setting(key, &original.to_string())?;
        }

        // Store TTL for restoration
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64);
        self.db.set_setting(
            "soar_rate_limit_expires",
            &expires_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        )?;

        // Apply reduced rates
        let new_packet = (current_packet as f64 * factor) as u64;
        let new_syn = (current_syn as f64 * factor) as u64;
        let new_udp = (current_udp as f64 * factor) as u64;
        let new_dns = (current_dns as f64 * factor) as u64;

        rate_limit.set_packet_rate(new_packet.max(1))?;
        rate_limit.set_syn_rate(new_syn.max(1))?;
        rate_limit.set_udp_rate(new_udp.max(1))?;
        rate_limit.set_dns_rate(new_dns.max(1))?;

        log!(SoarLog::RateLimitAdjusted(
            format!("{}", factor),
            ttl_secs,
            event.source_ip.clone(),
            event.attack_type.clone(),
            format!(
                "packet {}→{}, syn {}→{}, udp {}→{}, dns {}→{}",
                current_packet,
                new_packet.max(1),
                current_syn,
                new_syn.max(1),
                current_udp,
                new_udp.max(1),
                current_dns,
                new_dns.max(1),
            ),
        ));

        Ok(format!(
            "Rate limits reduced by factor {} for {}s (triggered by {})",
            factor, ttl_secs, event.source_ip
        ))
    }

    /// Send Telegram notification.
    async fn action_send_telegram(&self, event: &ThreatDetectedEvent) -> Result<String, Error> {
        if let Some(notifier) = &self.alert_notifier {
            let country = if let Some(geoip) = &self.geoip {
                if let Ok(ip_addr) = event.source_ip.parse::<std::net::IpAddr>() {
                    match geoip.lookup(ip_addr).await {
                        Ok(Some(loc)) => loc.country,
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let repeat_tag = if event.is_repeat_offender { " [REPEAT]" } else { "" };
            let payload = AlertPayload {
                source_ip: event.source_ip.clone(),
                dest_ip: event.dest_ip.clone(),
                country,
                threat_type: event.attack_type.clone(),
                confidence: event.confidence,
                action_description: format!(
                    "SOAR auto-response triggered (hits: {}{})",
                    event.flow_count, repeat_tag,
                ),
                timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            };
            notifier.send_alert(&payload).await?;
            Ok("Telegram notification sent".to_string())
        } else {
            log!(SoarLog::TelegramNotConfigured);
            Ok("Telegram not configured, skipped".to_string())
        }
    }

    /// Send email alert.
    async fn action_send_email(&self, event: &ThreatDetectedEvent) -> Result<String, Error> {
        // Build SmtpClient from settings stored via SoarPort::get_setting
        use crate::core::email::scheduler::SmtpClient;
        match SmtpClient::from_soar_port(&*self.db, self.secrets.as_deref())? {
            Some(smtp) => {
                let subject = format!(
                    "[NetGuardia] Threat Alert: {} from {}",
                    event.attack_type, event.source_ip
                );
                let body = format!(
                    "<h2>Threat Detected</h2>\
                     <p><b>Source IP:</b> {}</p>\
                     <p><b>Threat Type:</b> {}</p>\
                     <p><b>Confidence:</b> {:.1}%</p>\
                     <p><b>Time:</b> {}</p>",
                    event.source_ip,
                    event.attack_type,
                    event.confidence * 100.0,
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                );
                if let Some(recipient) = self.db.get_setting("smtp_recipient")? {
                    tokio::task::spawn_blocking(move || smtp.send(&recipient, &subject, &body))
                        .await
                        .map_err(|e| SoarError::ActionFailed {
                            action_type: "send_email".to_string(),
                            reason: e.to_string(),
                        })??;
                    Ok("Email alert sent".to_string())
                } else {
                    Ok("No SMTP recipient configured, skipped".to_string())
                }
            }
            None => Ok("SMTP not configured, skipped".to_string()),
        }
    }

    /// Send a webhook HTTP POST with SSRF DNS rebinding protection.
    /// Params: { "url": "https://example.com/hook", "timeout_secs": 10 }
    async fn action_webhook(&self, action: &PlaybookAction, event: &ThreatDetectedEvent) -> Result<String, Error> {
        let url_str = action
            .params
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| SoarError::ActionFailed {
                action_type: "webhook".to_string(),
                reason: "Missing 'url' parameter".to_string(),
            })?;

        let timeout_secs = action.params.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(10);

        // Parse URL and extract host
        let parsed_url = url::Url::parse(url_str).map_err(|e| SoarError::ActionFailed {
            action_type: "webhook".to_string(),
            reason: format!("Invalid URL: {}", e),
        })?;

        let host = parsed_url.host_str().ok_or_else(|| SoarError::ActionFailed {
            action_type: "webhook".to_string(),
            reason: "URL has no host".to_string(),
        })?;

        // DNS resolve all IPs and verify none are private/loopback/link-local
        let port = parsed_url.port_or_known_default().unwrap_or(443);
        let resolve_target = format!("{}:{}", host, port);
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&resolve_target)
            .await
            .map_err(|e| SoarError::ActionFailed {
                action_type: "webhook".to_string(),
                reason: format!("DNS resolution failed for '{}': {}", host, e),
            })?
            .collect();

        if addrs.is_empty() {
            return Err(SoarError::ActionFailed {
                action_type: "webhook".to_string(),
                reason: format!("DNS resolution returned no addresses for '{}'", host),
            }
            .into());
        }

        for addr in &addrs {
            if Self::is_private_ip(&addr.ip()) {
                log!(SoarLog::EventHandlingFailed(format!(
                    "SSRF blocked: webhook URL '{}' resolved to private IP {}",
                    url_str,
                    addr.ip()
                )));
                return Err(SoarError::ActionFailed {
                    action_type: "webhook".to_string(),
                    reason: format!("SSRF blocked: host '{}' resolves to private IP {}", host, addr.ip()),
                }
                .into());
            }
        }

        // Build and send the webhook payload (includes all enriched fields)
        let sources_str: Vec<String> = event.sources.iter().map(|s| s.to_string()).collect();
        let payload = serde_json::json!({
            "source_ip": event.source_ip,
            "dest_ip": event.dest_ip,
            "attack_type": event.attack_type,
            "confidence": event.confidence,
            "flow_count": event.flow_count,
            "packet_rate": event.packet_rate,
            "protocol": event.protocol,
            "geoip_country": event.geoip_country,
            "is_repeat_offender": event.is_repeat_offender,
            "detection_sources": sources_str,
            "timestamp": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        });

        // Pin resolved IPs to prevent DNS rebinding: the DNS check above verified
        // all resolved addresses are public, so we force reqwest to use those same
        // addresses instead of re-resolving (which could return a private IP on TTL expiry).
        let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(timeout_secs));
        for addr in &addrs {
            client_builder = client_builder.resolve(host, *addr);
        }
        let client = client_builder.build().map_err(|e| SoarError::ActionFailed {
            action_type: "webhook".to_string(),
            reason: format!("HTTP client error: {}", e),
        })?;

        let resp = client
            .post(url_str)
            .json(&payload)
            .send()
            .await
            .map_err(|e| SoarError::ActionFailed {
                action_type: "webhook".to_string(),
                reason: format!("HTTP request failed: {}", e),
            })?;

        let status = resp.status();
        if status.is_success() {
            Ok(format!("Webhook sent to {} (status {})", url_str, status))
        } else {
            Err(SoarError::ActionFailed {
                action_type: "webhook".to_string(),
                reason: format!("Webhook returned HTTP {}", status),
            }
            .into())
        }
    }

    /// Check if an IP address is private/loopback/link-local (SSRF protection).
    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()         // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()      // 169.254.0.0/16
                || v4.is_unspecified()     // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()           // ::1
                || v6.is_unspecified()     // ::
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // fc00::/7 (unique local: fc00::/8 + fd00::/8)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Log action.
    fn action_log(&self, action: &PlaybookAction, event: &ThreatDetectedEvent) -> Result<String, Error> {
        let level = action.params.get("level").and_then(|v| v.as_str()).unwrap_or("warn");

        log!(SoarLog::ActionLog(
            level.to_string(),
            event.source_ip.clone(),
            event.attack_type.clone(),
            format!("{:.2}", event.confidence),
        ));

        Ok(format!("Logged at level '{}'", level))
    }

    /// Fallback execution when no playbook matches.
    /// Only fires when source_ip is present.
    async fn execute_fallback(&self, event: &ThreatDetectedEvent) -> Result<(), Error> {
        // Check admin whitelist — never block admin IPs even in fallback
        if self.admin_whitelist.read().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                "fallback".to_string()
            ));
            return Ok(());
        }

        // Check cooldown — use playbook_id=-1 for fallback actions
        if self.is_cooldown_active(-1, &event.source_ip, 300) {
            log!(SoarLog::CooldownActive("fallback".to_string(), event.source_ip.clone()));
            return Ok(());
        }

        // Default fallback: block IP for 30 minutes + log
        let fake_action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": 1800}),
        };

        let block_result = self.execute_action(&fake_action, event, -1).await;
        let result_json = match &block_result {
            Ok(msg) => serde_json::json!({"action": "block_ip", "status": "ok", "message": msg}),
            Err(e) => serde_json::json!({"action": "block_ip", "status": "error", "message": e.to_string()}),
        };

        // Record cooldown for fallback
        self.record_cooldown(-1, &event.source_ip);

        // Audit trail with playbook_id = -1
        self.db.insert_soar_execution(
            -1,
            Some(&event.source_ip),
            &event.attack_type,
            &serde_json::to_string(&[result_json]).unwrap_or_default(),
        )?;

        log!(SoarLog::FallbackExecuted(event.source_ip.clone()));
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
            if let Err(e) = self.access_control.block_ip(source_ip).await {
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

            match self.access_control.unblock_ip(&source_ip).await {
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
        // Acquire lock to serialize rate limit read-save-write (Item 6: atomicity)
        let _guard = self.rate_limit_lock.lock().await;

        let expires_str = match self
            .db
            .get_setting("soar_rate_limit_expires")?
            .filter(|s| !s.is_empty())
        {
            Some(s) => s,
            None => return Ok(()), // No active adjustment
        };

        let expires = chrono::NaiveDateTime::parse_from_str(&expires_str, "%Y-%m-%d %H:%M:%S")
            .map(|dt| dt.and_utc())
            .unwrap_or_else(|_| chrono::Utc::now());

        if chrono::Utc::now() < expires {
            return Ok(()); // Not yet expired
        }

        // Restore original rates
        let original_str = match self
            .db
            .get_setting("soar_rate_limit_original")?
            .filter(|s| !s.is_empty())
        {
            Some(s) => s,
            None => {
                // No originals saved, just clean up
                self.db.set_setting("soar_rate_limit_expires", "")?;
                return Ok(());
            }
        };

        if let (Some(rate_limit), Ok(original)) = (
            &self.rate_limit,
            serde_json::from_str::<serde_json::Value>(&original_str),
        ) {
            let mut restore_errors = Vec::new();
            if let Some(v) = original.get("packet_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_packet_rate(v)
            {
                restore_errors.push(format!("packet_rate: {}", e));
            }
            if let Some(v) = original.get("syn_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_syn_rate(v)
            {
                restore_errors.push(format!("syn_rate: {}", e));
            }
            if let Some(v) = original.get("udp_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_udp_rate(v)
            {
                restore_errors.push(format!("udp_rate: {}", e));
            }
            if let Some(v) = original.get("dns_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_dns_rate(v)
            {
                restore_errors.push(format!("dns_rate: {}", e));
            }
            if restore_errors.is_empty() {
                log!(SoarLog::RateLimitRestored);
            } else {
                log!(SoarLog::RateLimitRestoreFailed(restore_errors.join(", ")));
            }
        }

        // Clean up settings
        self.db.set_setting("soar_rate_limit_original", "")?;
        self.db.set_setting("soar_rate_limit_expires", "")?;

        Ok(())
    }

    /// Remove expired cooldown entries to prevent unbounded growth.
    /// Called by TTL scheduler every 60 seconds.
    pub fn cleanup_expired_cooldowns(&self) {
        let max_cooldown_secs = {
            let playbooks = self.playbooks.read();
            playbooks.iter().map(|p| p.cooldown_secs as u64).max().unwrap_or(3600)
        };
        let expiry = std::time::Duration::from_secs(max_cooldown_secs.saturating_mul(2).max(3600));
        let before = self.cooldowns.len();
        self.cooldowns.retain(|_, instant| instant.elapsed() < expiry);
        let removed = before.saturating_sub(self.cooldowns.len());
        if removed > 0 {
            log!(SoarLog::CooldownCleanup(removed as u32));
        }

        // Also clean up empty frequency tracker entries
        let freq_removed = self.frequency_tracker.cleanup();
        if freq_removed > 0 {
            log!(SoarLog::FrequencyCleanup(freq_removed));
        }
    }

    /// Decrement the active block counter (called by TTL scheduler on unblock).
    /// Uses CAS loop to avoid underflow race condition.
    pub fn decrement_block_count(&self) {
        loop {
            let current = self.active_block_count.load(Ordering::SeqCst);
            if current == 0 {
                return; // Nothing to decrement
            }
            match self
                .active_block_count
                .compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(_) => continue, // Retry on contention
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::error::ebpf::EbpfError;
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

    #[async_trait::async_trait]
    impl crate::interface::port::access_control::AccessControlPort for MockAccessControl {
        async fn block_ip(&self, ip: &str) -> Result<(), Error> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(EbpfError::UnknownError.into());
            }
            self.blocked_ips.lock().push(ip.to_string());
            Ok(())
        }

        async fn unblock_ip(&self, ip: &str) -> Result<(), Error> {
            if self.should_fail.load(Ordering::SeqCst) {
                return Err(EbpfError::UnknownError.into());
            }
            self.unblocked_ips.lock().push(ip.to_string());
            Ok(())
        }
    }

    fn test_db() -> Arc<dyn SoarPort> {
        use crate::adapter::persistence::Database;
        Arc::new(Database::new(":memory:").expect("Failed to create test database")) as Arc<dyn SoarPort>
    }

    fn test_engine(ac: Arc<dyn crate::interface::port::access_control::AccessControlPort>) -> SoarEngine {
        let db = test_db();
        db.seed_default_playbooks().ok();
        // Tests expect enforce mode to be active so block_ip actions execute
        db.set_setting("enforce_mode", "enforce").ok();
        // enforce=2
        let cache = Arc::new(AtomicU8::new(2));
        SoarEngine::new(db, ac, None, None, None, cache, None).expect("Failed to create SOAR engine")
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
            sources: vec![crate::model::event::DetectionSource::ML],
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
            sources: vec![crate::model::event::DetectionSource::ML],
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
        let expires = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.insert_soar_block_rule("192.168.1.100", 1, &expires).ok();

        let cache = Arc::new(AtomicU8::new(2));
        let engine = SoarEngine::new(db, mock.clone(), None, None, None, cache, None).expect("Failed to create engine");
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

        let expires = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.insert_soar_block_rule("10.0.0.1", 1, &expires).ok();

        let cache = Arc::new(AtomicU8::new(2));
        let engine = SoarEngine::new(db, mock.clone(), None, None, None, cache, None).expect("Failed to create engine");

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
            sources: vec![crate::model::event::DetectionSource::ML],
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
            attack_type: "threat_detected".to_string(),
            confidence: 0.95,
            flow_count: 1,
            packet_rate: 0.0,
            protocol: 6,
            geoip_country: None,
            is_repeat_offender: false,
            sources: vec![crate::model::event::DetectionSource::ML],
        };

        // Find a matching playbook — default "threat_detected" playbook should exist
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
        let engine = SoarEngine::new(db, mock.clone(), None, None, None, cache, None).expect("Failed to create engine");

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
            sources: vec![crate::model::event::DetectionSource::ML],
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
        let engine = SoarEngine::new(db.clone(), mock, None, None, None, cache, None).expect("Failed to create engine");

        // Should have loaded default playbooks
        let count = engine.playbooks.read().len();
        assert!(count > 0, "Should have loaded default playbooks");

        // Add a new playbook directly to DB
        db.insert_playbook("test_pb", "port_scan", None, None, None, 60).ok();

        // Cache should not have it yet
        assert_eq!(engine.playbooks.read().len(), count);

        // After reload, should have one more
        engine.reload_cache().expect("reload should succeed");
        assert_eq!(engine.playbooks.read().len(), count + 1);
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
            sources: vec![crate::model::event::DetectionSource::ML],
        }
    }

    fn make_playbook(conditions: Vec<PlaybookCondition>) -> Playbook {
        Playbook {
            id: 999,
            name: "test-playbook".to_string(),
            trigger_event: "threat_detected".to_string(),
            condition_threshold: None,
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
