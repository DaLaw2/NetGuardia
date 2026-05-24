use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use macros::log;
use tokio::task::spawn_blocking;

use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::common::utils::ip_address::ip_version_from_str;
use crate::core::common::enforce_mode_handler::ENFORCE_LEVEL_ENFORCE;
use crate::core::response::engine::SoarEngine;
use crate::domain::common::event::{DetectionDiagnostic, ThreatDetectedEvent};
use crate::domain::common::notification::AlertPayload;
use crate::domain::response::error::SoarError;
use crate::domain::response::log::SoarLog;
use crate::domain::response::outcome::FallbackOutcome;
use crate::domain::response::playbook::{ActionType, Playbook, PlaybookAction, PlaybookActionParams};
use crate::interface::data_plane::access_control::AccessControlPort;

const RATE_LIMIT_FACTOR_MIN: f64 = 0.01;
const RATE_LIMIT_FACTOR_MAX: f64 = 1.0;
const FALLBACK_PLAYBOOK_ID: i64 = -1;

impl SoarEngine {
    pub fn is_enforce_mode(&self) -> bool {
        self.enforce_level_cache.load(Ordering::Relaxed) == ENFORCE_LEVEL_ENFORCE
    }

    pub async fn execute_playbook(&self, playbook: &Playbook, event: &ThreatDetectedEvent) -> Result<(), Error> {
        if self.is_cooldown_active(playbook.id, &event.source_ip, playbook.cooldown_secs) {
            log!(SoarLog::CooldownActive(playbook.name.clone(), event.source_ip.clone()));
            return Ok(());
        }

        if self.matcher.admin_whitelist.load().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                playbook.name.clone()
            ));
            return Ok(());
        }

        let mut action_results = Vec::new();
        for action in &playbook.actions {
            let result = self.execute_action(action, event, playbook.id).await;
            let result_json = match &result {
                Ok(msg) => {
                    serde_json::json!({"action": action.action_type.to_string(), "status": "ok", "message": msg})
                }
                Err(e) => {
                    serde_json::json!({"action": action.action_type.to_string(), "status": "error", "message": e.to_string()})
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

        self.record_cooldown(playbook.id, &event.source_ip);

        let actions_json = serde_json::to_string(&action_results).map_err(CodecError::SerializeFailed)?;
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

    pub async fn execute_action(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        match action.action_type {
            ActionType::BlockIp => {
                if !self.is_enforce_mode() {
                    log!(SoarLog::MonitorModeSkipped(
                        action.action_type.to_string(),
                        event.source_ip.clone()
                    ));
                    return Ok(format!("[monitor] Would block IP {} — skipped", event.source_ip));
                }
                self.action_block_ip(action, event, playbook_id).await
            }
            ActionType::AdjustRateLimit => {
                if !self.is_enforce_mode() {
                    log!(SoarLog::MonitorModeSkipped(
                        action.action_type.to_string(),
                        event.source_ip.clone()
                    ));
                    return Ok("[monitor] Would adjust rate limit — skipped".to_string());
                }
                self.action_adjust_rate_limit(action, event).await
            }
            ActionType::SendTelegram => self.action_send_telegram(event).await,
            ActionType::SendEmail => self.action_send_email(event).await,
            ActionType::Webhook => self.action_webhook(action, event).await,
            ActionType::Log => self.action_log(action, event),
        }
    }

    async fn action_block_ip(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
        playbook_id: i64,
    ) -> Result<String, Error> {
        let ttl_secs = action
            .params
            .ttl_secs
            .unwrap_or_else(|| self.matcher.config.load().soar.default_block_ttl_secs);

        let soar_cfg = self.matcher.config.load().soar.clone();
        let max_ttl = soar_cfg.max_ttl_secs;
        let max_cap = soar_cfg.max_auto_block_cap;
        validate_action_ttl(ttl_secs, max_ttl)?;
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
        if let Err(e) = block_ip_blocking(Arc::clone(&self.access_control), event.source_ip.clone()).await {
            self.decrement_block_count();
            return Err(e);
        }

        let expires_str = block_expiry_string(ttl_secs)?;
        let ip_version = ip_version_from_str(&event.source_ip)?;
        let commit_result = self
            .db
            .commit_soar_block_to_db(&event.source_ip, ip_version, playbook_id, &expires_str)
            .await;
        if let Err(e) = commit_result {
            let unblock_outcome = unblock_ip_blocking(Arc::clone(&self.access_control), event.source_ip.clone()).await;
            if let Err(unblock_err) = unblock_outcome {
                log!(SoarLog::BlockRollbackUnblockFailed(
                    event.source_ip.clone(),
                    unblock_err.to_string()
                ));
                if let Err(pend_err) = self.db.insert_pending_unblock(&event.source_ip).await {
                    log!(SoarLog::PendingUnblockQueueFailed(
                        event.source_ip.clone(),
                        pend_err.to_string()
                    ));
                }
            }
            self.decrement_block_count();
            return Err(e);
        }

        Ok(format!("Blocked IP {} for {}s", event.source_ip, ttl_secs))
    }

    async fn action_adjust_rate_limit(
        &self,
        action: &PlaybookAction,
        event: &ThreatDetectedEvent,
    ) -> Result<String, Error> {
        let owner = self.rate_limit.as_ref().ok_or(SoarError::RateLimitUnavailable)?;

        let soar_defaults = self.matcher.config.load().soar.clone();
        let factor = action.params.factor.unwrap_or(soar_defaults.default_rate_limit_factor);
        let ttl_secs = action
            .params
            .ttl_secs
            .unwrap_or(soar_defaults.default_rate_limit_ttl_secs);

        if !(RATE_LIMIT_FACTOR_MIN..=RATE_LIMIT_FACTOR_MAX).contains(&factor) {
            Err(SoarError::InvalidRateLimitFactor(factor))?;
        }

        let max_ttl = self.matcher.config.load().soar.max_ttl_secs;
        validate_action_ttl(ttl_secs, max_ttl)?;

        owner
            .adjust(factor, ttl_secs, event.source_ip.clone(), event.attack_type.clone())
            .await
    }

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
                timestamp: Utc::now().timestamp(),
            };
            notifier.send_alert(&payload).await?;
            Ok("Telegram notification sent".to_string())
        } else {
            log!(SoarLog::TelegramNotConfigured);
            Ok("Telegram not configured, skipped".to_string())
        }
    }

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

    async fn action_webhook(&self, action: &PlaybookAction, event: &ThreatDetectedEvent) -> Result<String, Error> {
        let url_str = action
            .params
            .url
            .as_deref()
            .ok_or_else(|| SoarError::WebhookMissingParam("url"))?;

        let timeout_secs = action
            .params
            .timeout_secs
            .unwrap_or_else(|| self.matcher.config.load().soar.default_webhook_timeout_secs);

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
            "detection_sources": &event.sources,
            "timestamp": Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        });

        let status = self.webhook_sender.post_json(url_str, timeout_secs, &payload).await?;
        if (200..300).contains(&status) {
            Ok(format!("Webhook sent to {} (status {})", url_str, status))
        } else {
            Err(SoarError::WebhookHttpStatus(status))?
        }
    }

    fn action_log(&self, action: &PlaybookAction, event: &ThreatDetectedEvent) -> Result<String, Error> {
        let level = action.params.level.as_deref().unwrap_or("warn");

        log!(SoarLog::ActionLog(
            level.to_string(),
            event.source_ip.clone(),
            event.attack_type.clone(),
            format!("{:.2}", event.confidence),
            format_diagnostics(&event.diagnostics),
        ));

        Ok(format!("Logged at level '{}'", level))
    }

    pub async fn execute_fallback(&self, event: &ThreatDetectedEvent) -> Result<FallbackOutcome, Error> {
        if self.matcher.admin_whitelist.load().contains(&event.source_ip) {
            log!(SoarLog::WhitelistSkipped(
                event.source_ip.clone(),
                "fallback".to_string()
            ));
            return Ok(FallbackOutcome::WhitelistSkipped);
        }
        let fallback_cfg = self.matcher.config.load().soar.clone();
        if self.is_cooldown_active(
            FALLBACK_PLAYBOOK_ID,
            &event.source_ip,
            fallback_cfg.fallback_cooldown_secs,
        ) {
            log!(SoarLog::CooldownActive("fallback".to_string(), event.source_ip.clone()));
            return Ok(FallbackOutcome::CooldownSkipped);
        }
        let fake_action = PlaybookAction {
            action_order: 1,
            action_type: ActionType::BlockIp,
            params: PlaybookActionParams {
                ttl_secs: Some(fallback_cfg.default_block_ttl_secs),
                ..Default::default()
            },
        };

        let block_result = self.execute_action(&fake_action, event, FALLBACK_PLAYBOOK_ID).await;
        let result_json = match &block_result {
            Ok(msg) => serde_json::json!({"action": "block_ip", "status": "ok", "message": msg}),
            Err(e) => serde_json::json!({"action": "block_ip", "status": "error", "message": e.to_string()}),
        };
        let outcome = if block_result.is_ok() {
            self.record_cooldown(FALLBACK_PLAYBOOK_ID, &event.source_ip);
            FallbackOutcome::Blocked
        } else {
            FallbackOutcome::BlockFailed
        };
        let actions_json = serde_json::to_string(&[result_json]).map_err(CodecError::SerializeFailed)?;
        self.db
            .insert_soar_execution(
                FALLBACK_PLAYBOOK_ID,
                Some(&event.source_ip),
                &event.attack_type,
                &actions_json,
            )
            .await?;

        log!(SoarLog::FallbackExecuted(event.source_ip.clone()));
        Ok(outcome)
    }
}

fn format_diagnostics(diagnostics: &[DetectionDiagnostic]) -> String {
    if diagnostics.is_empty() {
        return "none".to_string();
    }

    diagnostics
        .iter()
        .map(|diagnostic| format!("{}:{}={:.3}", diagnostic.source, diagnostic.name, diagnostic.value))
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_action_ttl(ttl_secs: u64, max_ttl: u64) -> Result<(), Error> {
    if ttl_secs == 0 {
        Err(SoarError::InvalidTtlNonPositive(ttl_secs))?;
    }
    if ttl_secs > max_ttl {
        Err(SoarError::InvalidTtl(ttl_secs, max_ttl))?;
    }
    let ttl_i64 = i64::try_from(ttl_secs).map_err(|_| SoarError::TtlTooLarge(ttl_secs))?;
    ChronoDuration::try_seconds(ttl_i64).ok_or(SoarError::TtlTooLarge(ttl_secs))?;
    if Instant::now().checked_add(Duration::from_secs(ttl_secs)).is_none() {
        Err(SoarError::TtlTooLarge(ttl_secs))?;
    }
    Ok(())
}

fn block_expiry_string(ttl_secs: u64) -> Result<String, Error> {
    let ttl_i64 = i64::try_from(ttl_secs).map_err(|_| SoarError::TtlTooLarge(ttl_secs))?;
    let ttl = ChronoDuration::try_seconds(ttl_i64).ok_or(SoarError::TtlTooLarge(ttl_secs))?;
    let expires_at = Utc::now()
        .checked_add_signed(ttl)
        .ok_or(SoarError::TtlTooLarge(ttl_secs))?;
    Ok(expires_at.format("%Y-%m-%d %H:%M:%S").to_string())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_action_ttl_rejects_values_above_configured_max() {
        let err = validate_action_ttl(61, 60).expect_err("ttl above max should fail");

        assert!(err.to_string().contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn validate_action_ttl_rejects_zero() {
        let err = validate_action_ttl(0, 60).expect_err("zero ttl should fail");

        assert!(
            err.to_string().contains("must be greater than 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_action_ttl_rejects_values_too_large_to_schedule() {
        let ttl = i64::MAX as u64 + 1;
        let err = validate_action_ttl(ttl, u64::MAX).expect_err("oversized ttl should fail");

        assert!(
            err.to_string().contains("too large to schedule safely"),
            "unexpected error: {err}"
        );
    }
}
