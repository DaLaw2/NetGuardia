//! SOAR application layer: playbook orchestration + action execution.
//!
//! Each action here reaches out to external systems (DB writes, eBPF blocks,
//! Telegram API, SMTP, webhooks). They are all invoked through `execute_action`
//! dispatch, which is itself called from `execute_playbook` after the domain
//! layer (`matcher.rs`) decided the playbook should fire.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use macros::log;
use reqwest::Client;
use tokio::net::lookup_host;
use tokio::task::spawn_blocking;
use url::Url;

use crate::core::playbook_service::ip_version_from_str;
use crate::core::soar::engine::SoarEngine;
use crate::interface::port::notification::AlertPayload;
use crate::model::error::Error;
use crate::model::error::soar::SoarError;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::soar::SoarLog;
use crate::model::soar::playbook::{Playbook, PlaybookAction};

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
            Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
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

        // Block IP via AccessControlPort (handles IPv4/IPv6 dispatch internally)
        if let Err(e) = self.access_control.block_ip(&event.source_ip).await {
            self.decrement_block_count();
            return Err(e);
        }

        // Calculate expiry time
        let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs as i64);
        let expires_str = expires_at.format("%Y-%m-%d %H:%M:%S").to_string();

        // tx-1 (R2 mitigation): atomically write soar_block_rules + acl_rules.
        // Either both commit or both roll back — no half-state possible.
        let ip_version = ip_version_from_str(&event.source_ip);
        if let Err(e) = self
            .db
            .commit_soar_block_to_db(&event.source_ip, ip_version, playbook_id, &expires_str)
        {
            // DB tx rolled back both rows; now roll back the eBPF block.
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
        let rate_limit = self.rate_limit.as_ref().ok_or(SoarError::RateLimitUnavailable)?;

        let factor = action.params.get("factor").and_then(|v| v.as_f64()).unwrap_or(0.5);
        let ttl_secs = action.params.get("ttl_secs").and_then(|v| v.as_u64()).unwrap_or(600);

        if !(0.01..=1.0).contains(&factor) {
            Err(SoarError::InvalidRateLimitFactor(factor))?;
        }

        let max_ttl: u64 = self
            .db
            .get_setting("soar_max_ttl_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400);
        if ttl_secs > max_ttl {
            Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
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
        let expires_at = Utc::now() + ChronoDuration::seconds(ttl_secs as i64);
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

        let timeout_secs = action.params.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(10);

        // Parse URL and extract host
        let parsed_url = Url::parse(url_str).map_err(|e| SoarError::ActionFailed("webhook", e))?;

        let host = parsed_url.host_str().ok_or(SoarError::WebhookUrlNoHost)?;

        // DNS resolve all IPs and verify none are private/loopback/link-local
        let port = parsed_url.port_or_known_default().unwrap_or(443);
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
}
