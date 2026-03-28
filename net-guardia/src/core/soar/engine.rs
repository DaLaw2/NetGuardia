use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use macros::log;
use tokio::sync::broadcast;

use crate::adapter::persistence::Database;
use crate::core::ebpf::rate_limit::RateLimitConfig;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::geoip::GeoIpService;
use crate::interface::communication::event_types::ThreatDetectedEvent;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::notification::{AlertNotifier, AlertPayload};
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::log::soar::SoarLog;
use crate::model::soar::playbook::{Playbook, PlaybookAction};

/// Maximum number of concurrent auto-blocked IPs.
const MAX_AUTO_BLOCK_CAP: u32 = 100;

/// Maximum TTL in seconds (24 hours).
const MAX_TTL_SECS: u64 = 86400;

/// Cooldown key: (playbook_id, source_ip)
type CooldownKey = (i64, String);

/// SOAR Engine — subscribes to ThreatDetectedEvent and executes matching playbooks.
pub struct SoarEngine {
    db: Arc<Database>,
    access_control: Arc<dyn AccessControlPort>,
    /// In-memory cache of playbooks (loaded at startup, refreshed on change).
    playbooks: parking_lot::RwLock<Vec<Playbook>>,
    /// In-memory cache of admin whitelist IPs.
    admin_whitelist: parking_lot::RwLock<HashSet<String>>,
    /// Cooldown tracker: maps (playbook_id, source_ip) → last execution time.
    cooldowns: DashMap<CooldownKey, std::time::Instant>,
    /// AtomicU32 counter for active auto-blocks (avoids DB query per event).
    active_block_count: AtomicU32,
    /// Optional alert notifier (Telegram, etc.).
    alert_notifier: Option<Arc<dyn AlertNotifier>>,
    /// Optional GeoIP service for country lookups.
    geoip: Option<Arc<GeoIpService>>,
    /// Optional rate limit config for adjust_rate_limit action.
    rate_limit: Option<Arc<RateLimitConfig>>,
}

impl SoarEngine {
    pub fn new(
        db: Arc<Database>,
        access_control: Arc<dyn AccessControlPort>,
        alert_notifier: Option<Arc<dyn AlertNotifier>>,
        geoip: Option<Arc<GeoIpService>>,
        rate_limit: Option<Arc<RateLimitConfig>>,
    ) -> Result<Self, Error> {
        let engine = Self {
            db,
            access_control,
            playbooks: parking_lot::RwLock::new(Vec::new()),
            admin_whitelist: parking_lot::RwLock::new(HashSet::new()),
            cooldowns: DashMap::new(),
            active_block_count: AtomicU32::new(0),
            alert_notifier,
            geoip,
            rate_limit,
        };
        engine.reload_cache()?;
        Ok(engine)
    }

    /// Load playbooks and admin whitelist from DB into memory.
    pub fn reload_cache(&self) -> Result<(), Error> {
        // Load playbooks via single JOIN query (no N+1)
        let rows = self.db.load_playbooks_with_actions()?;
        let mut playbooks: Vec<Playbook> = Vec::new();

        for (pb_id, name, enabled, trigger_event, threshold, _count, _window, cooldown,
             _action_id, action_order, action_type, action_params) in rows
        {
            // Check if this row belongs to the same playbook as the last one
            let needs_new = playbooks.last().is_none_or(|last| last.id != pb_id);
            if needs_new {
                playbooks.push(Playbook {
                    id: pb_id, name, enabled, trigger_event,
                    condition_threshold: threshold,
                    cooldown_secs: cooldown,
                    actions: Vec::new(),
                });
            }
            // Safe: we just pushed if empty, and last() was Some otherwise
            let Some(pb) = playbooks.last_mut() else {
                continue;
            };

            if let (Some(order), Some(atype), Some(params_str)) =
                (action_order, action_type, action_params)
            {
                pb.actions.push(PlaybookAction {
                    action_order: order,
                    action_type: atype,
                    params: serde_json::from_str(&params_str)
                        .unwrap_or(serde_json::Value::Object(Default::default())),
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
            log!(SoarLog::EventHandlingFailed(format!("CRITICAL: SOAR engine failed to subscribe — automated threat response is DISABLED: {}", e)));
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

    async fn event_loop(
        self: Arc<Self>,
        mut rx: broadcast::Receiver<ThreatDetectedEvent>,
    ) {
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
    async fn handle_threat_event(
        &self,
        event: &ThreatDetectedEvent,
    ) -> Result<(), Error> {
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

    /// Pure function: find playbooks matching the event.
    fn find_matching_playbooks(&self, event: &ThreatDetectedEvent) -> Vec<Playbook> {
        let playbooks = self.playbooks.read();
        playbooks
            .iter()
            .filter(|pb| {
                pb.enabled && pb.trigger_event == event.attack_type
            })
            .filter(|pb| {
                // Check threshold condition
                if let Some(threshold) = pb.condition_threshold
                    && (event.confidence as f64) < threshold {
                        return false;
                    }
                true
            })
            .cloned()
            .collect()
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
    async fn execute_playbook(
        &self,
        playbook: &Playbook,
        event: &ThreatDetectedEvent,
    ) -> Result<(), Error> {
        // Check cooldown
        if self.is_cooldown_active(playbook.id, &event.source_ip, playbook.cooldown_secs) {
            log!(SoarLog::CooldownActive(playbook.name.clone(), event.source_ip.clone()));
            return Ok(());
        }

        // Check admin whitelist
        if self.admin_whitelist.read().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(event.source_ip.clone(), playbook.name.clone()));
            return Ok(());
        }

        // Execute actions in order
        let mut action_results = Vec::new();
        for action in &playbook.actions {
            let result = self.execute_action(action, event, playbook.id).await;
            let result_json = match &result {
                Ok(msg) => serde_json::json!({"action": &action.action_type, "status": "ok", "message": msg}),
                Err(e) => serde_json::json!({"action": &action.action_type, "status": "error", "message": e.to_string()}),
            };
            action_results.push(result_json);
            if let Err(e) = result {
                log!(SoarLog::PlaybookError(playbook.name.clone(), format!("Action '{}': {}", action.action_type, e)));
            }
        }

        // Record cooldown
        self.record_cooldown(playbook.id, &event.source_ip);

        // Write audit trail
        let actions_json = serde_json::to_string(&action_results).unwrap_or_default();
        self.db.insert_soar_execution(
            playbook.id,
            Some(&event.source_ip),
            &event.attack_type,
            &actions_json,
        )?;

        log!(SoarLog::PlaybookExecuted(playbook.name.clone(), event.source_ip.clone(), event.attack_type.clone()));

        Ok(())
    }

    /// Check if the system is in enforce mode (as opposed to monitor mode).
    fn is_enforce_mode(&self) -> bool {
        self.db.get_setting("enforce_mode")
            .ok()
            .flatten()
            .map(|m| m == "enforce")
            .unwrap_or(false)
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
                    log!(SoarLog::MonitorModeSkipped(action.action_type.clone(), event.source_ip.clone()));
                    return Ok(format!("[monitor] Would block IP {} — skipped", event.source_ip));
                }
                self.action_block_ip(action, event, playbook_id).await
            }
            "adjust_rate_limit" => {
                if !self.is_enforce_mode() {
                    log!(SoarLog::MonitorModeSkipped(action.action_type.clone(), event.source_ip.clone()));
                    return Ok("[monitor] Would adjust rate limit — skipped".to_string());
                }
                self.action_adjust_rate_limit(action, event).await
            }
            "send_telegram" => self.action_send_telegram(event).await,
            "send_email" => self.action_send_email(event).await,
            "log" => self.action_log(action, event),
            other => {
                Err(SoarError::ActionFailed {
                    action_type: other.to_string(),
                    reason: "Unknown action type".to_string(),
                }.into())
            }
        }
    }

    /// Block an IP via eBPF ACL with TTL.
    async fn action_block_ip(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        let ttl_secs = action.params.get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(1800);

        // Validate TTL
        if ttl_secs > MAX_TTL_SECS {
            return Err(SoarError::InvalidTtl {
                ttl_secs,
                max_secs: MAX_TTL_SECS,
            }.into());
        }

        // Atomically check cap and reserve a slot using CAS loop
        loop {
            let current_count = self.active_block_count.load(Ordering::SeqCst);
            if current_count >= MAX_AUTO_BLOCK_CAP {
                log!(SoarLog::CapReached(current_count, MAX_AUTO_BLOCK_CAP, event.source_ip.clone()));
                return Err(SoarError::CapReached { max_cap: MAX_AUTO_BLOCK_CAP }.into());
            }
            if self.active_block_count.compare_exchange(
                current_count,
                current_count + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ).is_ok() {
                break;
            }
        }

        // Block IP via AccessControlPort (handles IPv4/IPv6 dispatch internally)
        if let Err(e) = self.access_control.block_ip(&event.source_ip).await {
            self.decrement_block_count();
            return Err(e);
        }

        // Calculate expiry time
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(ttl_secs as i64);
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

        // Record in soar_block_rules
        if let Err(e) = self.db.insert_soar_block_rule(
            &event.source_ip,
            playbook_id,
            &expires_str,
        ) {
            // Attempt to roll back the eBPF block — log failure to prevent silent orphan blocks
            if let Err(unblock_err) = self.access_control.unblock_ip(&event.source_ip).await {
                log!(SoarLog::EventHandlingFailed(format!(
                    "CRITICAL: Failed to unblock IP {} after DB error — orphan eBPF block may exist: {}",
                    event.source_ip, unblock_err
                )));
            }
            self.decrement_block_count();
            return Err(e);
        }

        // Also persist to acl_rules for consistency
        let ip_version = crate::core::playbook_service::ip_version_from_str(&event.source_ip);
        self.db.insert_acl_rule(ip_version, "source", "blacklist", &event.source_ip, 0)?;

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
        let rate_limit = self.rate_limit.as_ref().ok_or_else(|| {
            SoarError::ActionFailed {
                action_type: "adjust_rate_limit".to_string(),
                reason: "Rate limit config not available".to_string(),
            }
        })?;

        let factor = action.params.get("factor")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5);
        let ttl_secs = action.params.get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(600);

        if !(0.01..=1.0).contains(&factor) {
            return Err(SoarError::ActionFailed {
                action_type: "adjust_rate_limit".to_string(),
                reason: format!("factor must be 0.01..1.0, got {}", factor),
            }.into());
        }

        if ttl_secs > MAX_TTL_SECS {
            return Err(SoarError::InvalidTtl { ttl_secs, max_secs: MAX_TTL_SECS }.into());
        }

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
                current_packet, new_packet.max(1),
                current_syn, new_syn.max(1),
                current_udp, new_udp.max(1),
                current_dns, new_dns.max(1),
            ),
        ));

        Ok(format!(
            "Rate limits reduced by factor {} for {}s (triggered by {})",
            factor, ttl_secs, event.source_ip
        ))
    }

    /// Send Telegram notification.
    async fn action_send_telegram(
        &self,
        event: &ThreatDetectedEvent,
    ) -> Result<String, Error> {
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
            let payload = AlertPayload {
                source_ip: event.source_ip.clone(),
                dest_ip: event.dest_ip.clone(),
                country,
                threat_type: event.attack_type.clone(),
                confidence: event.confidence,
                action_description: "SOAR auto-response triggered".to_string(),
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
    async fn action_send_email(
        &self,
        event: &ThreatDetectedEvent,
    ) -> Result<String, Error> {
        // Use existing SMTP infrastructure
        use crate::core::email::scheduler::SmtpClient;
        match SmtpClient::from_database(&*self.db)? {
            Some(smtp) => {
                let subject = format!("[NetGuardia] Threat Alert: {} from {}", event.attack_type, event.source_ip);
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
                    tokio::task::spawn_blocking(move || smtp.send(&recipient, &subject, &body)).await
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

    /// Log action.
    fn action_log(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
    ) -> Result<String, Error> {
        let level = action.params.get("level")
            .and_then(|v| v.as_str())
            .unwrap_or("warn");

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
    async fn execute_fallback(
        &self,
        event: &ThreatDetectedEvent,
    ) -> Result<(), Error> {
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

    /// Restore original rate limits if the TTL has expired.
    /// Called by TTL scheduler on each sweep.
    pub fn check_rate_limit_restoration(&self) -> Result<(), Error> {
        let expires_str = match self.db.get_setting("soar_rate_limit_expires")?.filter(|s| !s.is_empty()) {
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
        let original_str = match self.db.get_setting("soar_rate_limit_original")?.filter(|s| !s.is_empty()) {
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
                && let Err(e) = rate_limit.set_packet_rate(v) {
                restore_errors.push(format!("packet_rate: {}", e));
            }
            if let Some(v) = original.get("syn_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_syn_rate(v) {
                restore_errors.push(format!("syn_rate: {}", e));
            }
            if let Some(v) = original.get("udp_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_udp_rate(v) {
                restore_errors.push(format!("udp_rate: {}", e));
            }
            if let Some(v) = original.get("dns_rate").and_then(|v| v.as_u64())
                && let Err(e) = rate_limit.set_dns_rate(v) {
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

    /// Decrement the active block counter (called by TTL scheduler on unblock).
    /// Uses CAS loop to avoid underflow race condition.
    pub fn decrement_block_count(&self) {
        loop {
            let current = self.active_block_count.load(Ordering::SeqCst);
            if current == 0 {
                return; // Nothing to decrement
            }
            match self.active_block_count.compare_exchange(
                current,
                current - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(_) => continue, // Retry on contention
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use parking_lot::Mutex;
    use crate::model::error::ebpf::EbpfError;

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

    fn test_db() -> Arc<Database> {
        Arc::new(Database::new(":memory:").expect("Failed to create test database"))
    }

    fn test_engine(ac: Arc<dyn crate::interface::port::access_control::AccessControlPort>) -> SoarEngine {
        let db = test_db();
        db.seed_default_playbooks().ok();
        // Tests expect enforce mode to be active so block_ip actions execute
        db.set_setting("enforce_mode", "enforce").ok();
        SoarEngine::new(db, ac, None, None, None).expect("Failed to create SOAR engine")
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

        let engine = SoarEngine::new(db, mock.clone(), None, None, None)
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

        let expires = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        db.insert_soar_block_rule("10.0.0.1", 1, &expires).ok();

        let engine = SoarEngine::new(db, mock.clone(), None, None, None)
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

        // Set counter to max
        engine.active_block_count.store(MAX_AUTO_BLOCK_CAP, Ordering::SeqCst);

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence: 0.95,
        };

        let action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": 600}),
        };

        let result = engine.execute_action(&action, &event, 1).await;
        assert!(result.is_err(), "Should fail when cap is reached");
        assert!(mock.blocked_ips.lock().is_empty(), "Should not call block_ip when cap reached");
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

        let engine = SoarEngine::new(db, mock.clone(), None, None, None)
            .expect("Failed to create engine");

        let event = ThreatDetectedEvent {
            source_ip: "1.2.3.4".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            attack_type: "threat_detected".to_string(),
            confidence: 0.95,
        };

        let playbooks = engine.find_matching_playbooks(&event);
        assert!(!playbooks.is_empty());

        let result = engine.execute_playbook(&playbooks[0], &event).await;
        assert!(result.is_ok());
        assert!(mock.blocked_ips.lock().is_empty(), "Whitelisted IP should not be blocked");
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

        let engine = SoarEngine::new(db.clone(), mock, None, None, None)
            .expect("Failed to create engine");

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
}
