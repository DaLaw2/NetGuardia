//! SOAR application layer: playbook orchestration + action execution.
//!
//! Each action here reaches out to external systems (DB writes, eBPF blocks,
//! Telegram API, SMTP, webhooks). They are all invoked through `execute_action`
//! dispatch, which is itself called from `execute_playbook` after the domain
//! layer (`matcher.rs`) decided the playbook should fire.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use macros::log;
use reqwest::Client;
use tokio::net::lookup_host;
use tokio::task::spawn_blocking;
use url::Url;

use crate::core::email::scheduler::SmtpClient;
use crate::core::playbook_service::ip_version_from_str;
use crate::core::soar::engine::SoarEngine;
use crate::interface::port::access_control::AccessControlPort;
use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::notification::AlertPayload;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::soar::SoarLog;
use crate::model::soar::playbook::{Playbook, PlaybookAction};

/// Default block TTL when a `block_ip` action omits `ttl_secs`.
const DEFAULT_BLOCK_TTL_SECS: u64 = 1800;
/// DB-overridable cap on per-block TTL — see setting `soar_max_ttl_secs`.
const DEFAULT_SOAR_MAX_TTL_SECS: u64 = 86_400;
/// DB-overridable cap on concurrent SOAR-driven blocks — see setting
/// `soar_max_auto_block_cap`.
const DEFAULT_SOAR_MAX_AUTO_BLOCK_CAP: u32 = 100;
/// Default rate-limit reduction factor when an `adjust_rate_limit` action
/// omits `factor`. 0.5 = halve the current rate.
const DEFAULT_RATE_LIMIT_FACTOR: f64 = 0.5;
/// Default rate-limit TTL when an `adjust_rate_limit` action omits `ttl_secs`.
const DEFAULT_RATE_LIMIT_TTL_SECS: u64 = 600;
/// Lower bound on the rate-limit factor — anything below 1% of current
/// would brick traffic flow.
const RATE_LIMIT_FACTOR_MIN: f64 = 0.01;
/// Upper bound on the rate-limit factor — `1.0` is a no-op; values above
/// would *raise* the limit, which isn't a SOAR mitigation.
const RATE_LIMIT_FACTOR_MAX: f64 = 1.0;
/// Default webhook timeout when an action omits `timeout_secs`.
const DEFAULT_WEBHOOK_TIMEOUT_SECS: u64 = 10;
/// Fallback port when the webhook URL has no explicit port and no
/// well-known scheme port.
const DEFAULT_WEBHOOK_HTTPS_PORT: u16 = 443;
/// Sentinel `playbook_id` used by the no-matching-playbook fallback path.
/// `-1` is reserved on the audit / cooldown maps and never assigned to a
/// real DB playbook row.
const FALLBACK_PLAYBOOK_ID: i64 = -1;
/// Cooldown applied to the fallback path so a single noisy IP doesn't
/// spam the WORM audit chain on every fused detection.
const FALLBACK_COOLDOWN_SECS: i64 = 300;

impl SoarEngine {
    /// Check if the system is in enforce mode (as opposed to monitor mode).
    /// Reads from the in-memory AtomicU8 cache: Monitor=0, MlOnly=1, Enforce=2.
    pub(super) fn is_enforce_mode(&self) -> bool {
        self.enforce_level_cache.load(Ordering::Relaxed) == 2
    }

    /// Execute a single playbook against an event.
    pub(super) async fn execute_playbook(&self, playbook: &Playbook, event: &ThreatDetectedEvent) -> Result<(), Error> {
        // Check cooldown
        if self.is_cooldown_active(playbook.id, &event.source_ip, playbook.cooldown_secs) {
            log!(SoarLog::CooldownActive(playbook.name.clone(), event.source_ip.clone()));
            return Ok(());
        }

        // Check admin whitelist
        if self.admin_whitelist.load().contains(&event.source_ip) {
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

    /// Execute a single action.
    pub(super) async fn execute_action(
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
            other => Err(SoarError::UnknownActionType(other))?,
        }
    }

    /// Block an IP via eBPF ACL with TTL.
    async fn action_block_ip(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        let ttl_secs = action
            .params
            .get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_BLOCK_TTL_SECS);

        // Two settings read together off the tokio worker thread — r2d2's
        // pool.get() and rusqlite are blocking, so back-to-back calls inside
        // an async fn can stall the executor under burst load.
        let (max_ttl, max_cap) = read_block_caps(self.db.clone()).await?;
        if ttl_secs > max_ttl {
            Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
        }

        // Atomically check cap and reserve a slot using CAS loop.
        loop {
            let current_count = self.active_block_count.load(Ordering::SeqCst);
            if current_count >= max_cap {
                log!(SoarLog::CapReached(current_count, max_cap, event.source_ip.clone()));
                Err(SoarError::CapReached(max_cap))?;
            }
            if self
                .active_block_count
                .compare_exchange(current_count, current_count + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }

        // Block IP via AccessControlPort (handles IPv4/IPv6 dispatch internally).
        // Offloaded to `spawn_blocking` so the tokio worker is not stuck while
        // parking_lot::RwLock + aya map syscalls run — under SOAR burst with
        // `active_block_count` approaching `max_cap`, this keeps the rest of
        // the runtime responsive.
        if let Err(e) = block_ip_blocking(Arc::clone(&self.access_control), event.source_ip.clone()).await {
            self.decrement_block_count();
            return Err(e);
        }

        // Calculate expiry time
        let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs as i64);
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

        // Atomically write soar_block_rules + acl_rules. Either both commit
        // or both roll back — no half-state possible. Offloaded so the
        // SQLite WAL fsync can't block the tokio worker.
        let ip_version = ip_version_from_str(&event.source_ip);
        let commit_result = commit_block_blocking(
            self.db.clone(),
            event.source_ip.clone(),
            ip_version,
            playbook_id,
            expires_str.clone(),
        )
        .await;
        if let Err(e) = commit_result {
            // DB tx rolled back both rows; now roll back the eBPF block.
            let unblock_outcome = unblock_ip_blocking(Arc::clone(&self.access_control), event.source_ip.clone()).await;
            if let Err(unblock_err) = unblock_outcome {
                log!(SoarLog::EventHandlingFailed(format!(
                    "CRITICAL: Failed to unblock IP {} after DB error — queueing for retry: {}",
                    event.source_ip, unblock_err
                )));
                // Write to pending_unblock table so recovery can retry later
                if let Err(pend_err) = insert_pending_unblock_blocking(self.db.clone(), event.source_ip.clone()).await {
                    log!(SoarLog::EventHandlingFailed(format!(
                        "CRITICAL: Failed to queue pending unblock for IP {}: {}",
                        event.source_ip, pend_err
                    )));
                }
            }
            self.decrement_block_count();
            return Err(e);
        }

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
        let owner = self.rate_limit.as_ref().ok_or(SoarError::RateLimitUnavailable)?;

        let factor = action
            .params
            .get("factor")
            .and_then(|v| v.as_f64())
            .unwrap_or(DEFAULT_RATE_LIMIT_FACTOR);
        let ttl_secs = action
            .params
            .get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_RATE_LIMIT_TTL_SECS);

        if !(RATE_LIMIT_FACTOR_MIN..=RATE_LIMIT_FACTOR_MAX).contains(&factor) {
            Err(SoarError::InvalidRateLimitFactor(factor))?;
        }

        let max_ttl = read_max_ttl(self.db.clone()).await;
        if ttl_secs > max_ttl {
            Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
        }

        owner
            .adjust(factor, ttl_secs, event.source_ip.clone(), event.attack_type.clone())
            .await
    }

    /// Send Telegram notification.
    async fn action_send_telegram(&self, event: &ThreatDetectedEvent) -> Result<String, Error> {
        if let Some(notifier) = &self.alert_notifier {
            let country = if let Some(geoip) = &self.geoip {
                if let Ok(ip_addr) = event.source_ip.parse::<IpAddr>() {
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
                timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
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
                    Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
                );
                if let Some(recipient) = self.db.get_setting("smtp_recipient")? {
                    spawn_blocking(move || smtp.send(&recipient, &subject, &body))
                        .await
                        .map_err(|e| SoarError::ActionFailed("send_email", e))??;
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
            .ok_or_else(|| SoarError::WebhookMissingParam("url"))?;

        let timeout_secs = action
            .params
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_WEBHOOK_TIMEOUT_SECS);

        // Parse URL and extract host
        let parsed_url = Url::parse(url_str).map_err(|e| SoarError::ActionFailed("webhook", e))?;

        let host = parsed_url.host_str().ok_or(SoarError::WebhookUrlNoHost)?;

        // DNS resolve all IPs and verify none are private/loopback/link-local
        let port = parsed_url.port_or_known_default().unwrap_or(DEFAULT_WEBHOOK_HTTPS_PORT);
        let resolve_target = format!("{}:{}", host, port);
        let addrs: Vec<SocketAddr> = lookup_host(&resolve_target)
            .await
            .map_err(|e| SoarError::ActionFailed(format!("webhook (DNS for {})", host), e))?
            .collect();

        if addrs.is_empty() {
            Err(SoarError::WebhookDnsEmpty(host))?;
        }

        for addr in &addrs {
            if Self::is_private_ip(&addr.ip()) {
                log!(SoarLog::EventHandlingFailed(format!(
                    "SSRF blocked: webhook URL '{}' resolved to private IP {}",
                    url_str,
                    addr.ip()
                )));
                Err(SoarError::WebhookSsrfBlocked(host, addr.ip().to_string()))?;
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
            "timestamp": Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        });

        // Pin resolved IPs to prevent DNS rebinding: the DNS check above verified
        // all resolved addresses are public, so we force reqwest to use those same
        // addresses instead of re-resolving (which could return a private IP on TTL expiry).
        let mut client_builder = Client::builder().timeout(Duration::from_secs(timeout_secs));
        for addr in &addrs {
            client_builder = client_builder.resolve(host, *addr);
        }
        let client = client_builder
            .build()
            .map_err(|e| SoarError::ActionFailed("webhook", e))?;

        let resp = client
            .post(url_str)
            .json(&payload)
            .send()
            .await
            .map_err(|e| SoarError::ActionFailed("webhook", e))?;

        let status = resp.status();
        if status.is_success() {
            Ok(format!("Webhook sent to {} (status {})", url_str, status))
        } else {
            Err(SoarError::WebhookHttpStatus(status.as_u16()))?
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
            format!("{:.3}", event.ae_score),
            format!("{:.3}", event.anomaly_score),
            format!("{:.3}", event.c2_score),
        ));

        Ok(format!("Logged at level '{}'", level))
    }

    /// Fallback execution when no playbook matches.
    /// Only fires when source_ip is present.
    pub(super) async fn execute_fallback(&self, event: &ThreatDetectedEvent) -> Result<(), Error> {
        // Check admin whitelist — never block admin IPs even in fallback
        if self.admin_whitelist.load().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                "fallback".to_string()
            ));
            return Ok(());
        }

        // Check cooldown — uses FALLBACK_PLAYBOOK_ID as the synthetic key
        if self.is_cooldown_active(FALLBACK_PLAYBOOK_ID, &event.source_ip, FALLBACK_COOLDOWN_SECS) {
            log!(SoarLog::CooldownActive("fallback".to_string(), event.source_ip.clone()));
            return Ok(());
        }

        // Default fallback: block IP for the default block TTL + log
        let fake_action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": DEFAULT_BLOCK_TTL_SECS}),
        };

        let block_result = self.execute_action(&fake_action, event, FALLBACK_PLAYBOOK_ID).await;
        let result_json = match &block_result {
            Ok(msg) => serde_json::json!({"action": "block_ip", "status": "ok", "message": msg}),
            Err(e) => serde_json::json!({"action": "block_ip", "status": "error", "message": e.to_string()}),
        };

        // Record cooldown for fallback
        self.record_cooldown(FALLBACK_PLAYBOOK_ID, &event.source_ip);

        // Audit trail under the fallback synthetic playbook id
        self.db.insert_soar_execution(
            FALLBACK_PLAYBOOK_ID,
            Some(&event.source_ip),
            &event.attack_type,
            &serde_json::to_string(&[result_json]).unwrap_or_default(),
        )?;

        log!(SoarLog::FallbackExecuted(event.source_ip.clone()));
        Ok(())
    }
}

/// Read both block-related caps in a single offloaded blocking call so the
/// async caller pays one spawn_blocking hop instead of two.
async fn read_block_caps(db: Arc<dyn AppRepo>) -> Result<(u64, u32), Error> {
    spawn_blocking(move || {
        let max_ttl: u64 = db
            .get_setting("soar_max_ttl_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SOAR_MAX_TTL_SECS);
        let max_cap: u32 = db
            .get_setting("soar_max_auto_block_cap")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SOAR_MAX_AUTO_BLOCK_CAP);
        Ok::<_, Error>((max_ttl, max_cap))
    })
    .await
    .map_err(|e| SoarError::ActionFailed("read_block_caps", e))?
}

async fn read_max_ttl(db: Arc<dyn AppRepo>) -> u64 {
    spawn_blocking(move || {
        db.get_setting("soar_max_ttl_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_SOAR_MAX_TTL_SECS)
    })
    .await
    .unwrap_or(DEFAULT_SOAR_MAX_TTL_SECS)
}

async fn commit_block_blocking(
    db: Arc<dyn AppRepo>,
    source_ip: String,
    ip_version: u8,
    playbook_id: i64,
    expires_str: String,
) -> Result<(), Error> {
    spawn_blocking(move || db.commit_soar_block_to_db(&source_ip, ip_version, playbook_id, &expires_str))
        .await
        .map_err(|e| SoarError::ActionFailed("commit_soar_block_to_db", e))??;
    Ok(())
}

async fn insert_pending_unblock_blocking(db: Arc<dyn AppRepo>, source_ip: String) -> Result<i64, Error> {
    spawn_blocking(move || db.insert_pending_unblock(&source_ip))
        .await
        .map_err(|e| SoarError::ActionFailed("insert_pending_unblock", e))?
}

/// Offload `AccessControlPort::block_ip` onto a blocking thread. The port is
/// synchronous because its eBPF-map critical sections are tiny (microseconds),
/// but under SOAR burst many tokio workers would contend on the same
/// `parking_lot::RwLock` and the aya syscall itself blocks the executor.
async fn block_ip_blocking(access_control: Arc<dyn AccessControlPort>, ip: String) -> Result<(), Error> {
    spawn_blocking(move || access_control.block_ip(&ip))
        .await
        .map_err(|e| SoarError::ActionFailed("block_ip", e))?
}

async fn unblock_ip_blocking(access_control: Arc<dyn AccessControlPort>, ip: String) -> Result<(), Error> {
    spawn_blocking(move || access_control.unblock_ip(&ip))
        .await
        .map_err(|e| SoarError::ActionFailed("unblock_ip", e))?
}
