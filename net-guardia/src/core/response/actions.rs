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

use crate::core::response::engine::SoarEngine;
use crate::domain::common::error::Error;
use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::common::notification::AlertPayload;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::domain::response::playbook::{Playbook, PlaybookAction};
use crate::interface::access_control::AccessControlPort;
use crate::utils::ip_address::{ip_version_from_str, is_private_ip};

/// Lower bound on the rate-limit factor — anything below 1% of current
/// would brick traffic flow.
const RATE_LIMIT_FACTOR_MIN: f64 = 0.01;
/// Upper bound on the rate-limit factor — `1.0` is a no-op; values above
/// would *raise* the limit, which isn't a SOAR mitigation.
const RATE_LIMIT_FACTOR_MAX: f64 = 1.0;
/// Fallback port when the webhook URL has no explicit port and no
/// well-known scheme port.
const DEFAULT_WEBHOOK_HTTPS_PORT: u16 = 443;
/// Sentinel `playbook_id` used by the no-matching-playbook fallback path.
/// `-1` is reserved on the audit / cooldown maps and never assigned to a
/// real DB playbook row.
const FALLBACK_PLAYBOOK_ID: i64 = -1;

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
        if self.matcher.admin_whitelist.load().contains(&event.source_ip) {
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
            .insert_soar_execution(playbook.id, Some(&event.source_ip), &event.attack_type, &actions_json)
            .await?;

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
            .unwrap_or_else(|| self.matcher.config.load().soar.default_block_ttl_secs);

        let soar_cfg = self.matcher.config.load().soar.clone();
        let max_ttl = soar_cfg.max_ttl_secs;
        let max_cap = soar_cfg.max_auto_block_cap;
        if ttl_secs > max_ttl {
            Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
        }

        // Atomically check cap and reserve a slot using CAS loop.
        loop {
            let current_count = self.matcher.active_block_count.load(Ordering::SeqCst);
            if current_count >= max_cap {
                log!(SoarLog::CapReached(current_count, max_cap, event.source_ip.clone()));
                Err(SoarError::CapReached(max_cap))?;
            }
            if self
                .matcher
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
        // or both roll back — no half-state possible.
        let ip_version = ip_version_from_str(&event.source_ip);
        let commit_result = self
            .db
            .commit_soar_block_to_db(&event.source_ip, ip_version, playbook_id, &expires_str)
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
                if let Err(pend_err) = self.db.insert_pending_unblock(&event.source_ip).await {
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

        let soar_defaults = self.matcher.config.load().soar.clone();
        let factor = action
            .params
            .get("factor")
            .and_then(|v| v.as_f64())
            .unwrap_or(soar_defaults.default_rate_limit_factor);
        let ttl_secs = action
            .params
            .get("ttl_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(soar_defaults.default_rate_limit_ttl_secs);

        if !(RATE_LIMIT_FACTOR_MIN..=RATE_LIMIT_FACTOR_MAX).contains(&factor) {
            Err(SoarError::InvalidRateLimitFactor(factor))?;
        }

        let max_ttl = self.matcher.config.load().soar.max_ttl_secs;
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
                    geoip.lookup(ip_addr).await.and_then(|loc| loc.country)
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
        let smtp_cfg = self.matcher.config.load().notification.smtp.clone();
        match self
            .email_sender_factory
            .build_smtp_sender(&smtp_cfg, self.secrets.as_deref())
            .await?
        {
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
                if !smtp_cfg.recipient.is_empty() {
                    let recipient = smtp_cfg.recipient;
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
            .unwrap_or_else(|| self.matcher.config.load().soar.default_webhook_timeout_secs);

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
            if is_private_ip(&addr.ip()) {
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
        if self.matcher.admin_whitelist.load().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                "fallback".to_string()
            ));
            return Ok(());
        }

        // Check cooldown — uses FALLBACK_PLAYBOOK_ID as the synthetic key
        let fallback_cfg = self.matcher.config.load().soar.clone();
        if self.is_cooldown_active(
            FALLBACK_PLAYBOOK_ID,
            &event.source_ip,
            fallback_cfg.fallback_cooldown_secs,
        ) {
            log!(SoarLog::CooldownActive("fallback".to_string(), event.source_ip.clone()));
            return Ok(());
        }

        // Default fallback: block IP for the default block TTL + log
        let fake_action = PlaybookAction {
            action_order: 1,
            action_type: "block_ip".to_string(),
            params: serde_json::json!({"ttl_secs": fallback_cfg.default_block_ttl_secs}),
        };

        let block_result = self.execute_action(&fake_action, event, FALLBACK_PLAYBOOK_ID).await;
        let result_json = match &block_result {
            Ok(msg) => serde_json::json!({"action": "block_ip", "status": "ok", "message": msg}),
            Err(e) => serde_json::json!({"action": "block_ip", "status": "error", "message": e.to_string()}),
        };

        // Record cooldown for fallback
        self.record_cooldown(FALLBACK_PLAYBOOK_ID, &event.source_ip);

        // Audit trail under the fallback synthetic playbook id
        self.db
            .insert_soar_execution(
                FALLBACK_PLAYBOOK_ID,
                Some(&event.source_ip),
                &event.attack_type,
                &serde_json::to_string(&[result_json]).unwrap_or_default(),
            )
            .await?;

        log!(SoarLog::FallbackExecuted(event.source_ip.clone()));
        Ok(())
    }
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
