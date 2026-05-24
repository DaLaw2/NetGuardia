use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use macros::log;
use reqwest::Client;
use tokio::time::sleep;

use crate::common::error::Error;
use crate::common::error::notification::NotificationError;
use crate::common::log::notification::NotificationLog;
use crate::domain::common::config::AppConfig;
use crate::domain::common::notification::AlertPayload;
use crate::interface::response::notification::{AlertNotifier, AlertNotifierFactory};
use crate::interface::system::config_repo::ConfigRepo;
use crate::interface::system::secret_store::SecretStorePort;

pub struct TelegramAdapter {
    client: Client,
    notif: Arc<dyn ConfigRepo + Send + Sync>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    rate_state: AtomicU64,
}

impl TelegramAdapter {
    pub fn new(
        notif: Arc<dyn ConfigRepo + Send + Sync>,
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| NotificationError::TelegramRequestFailed(e.without_url()))?;

        Ok(Self {
            client,
            notif,
            config,
            secrets,
            rate_state: AtomicU64::new(0),
        })
    }

    async fn get_config(&self) -> Result<Option<(String, String)>, Error> {
        match self.notif.get_notification_config("telegram").await? {
            Some(json_str) => {
                let config: serde_json::Value =
                    serde_json::from_str(&json_str).map_err(NotificationError::TelegramRequestFailed)?;
                let mut token = config.get("bot_token").and_then(|v| v.as_str()).map(|s| s.to_string());
                let chat_id = config.get("chat_id").and_then(|v| v.as_str()).map(|s| s.to_string());
                if token.as_deref() == Some("__encrypted__")
                    && let Some(ss) = self.secrets.as_ref()
                {
                    token = ss.get_secret("telegram_bot_token").await?;
                }

                match (token, chat_id) {
                    (Some(t), Some(c)) if !t.is_empty() && !c.is_empty() => Ok(Some((t, c))),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    fn rate_limit_max_messages(&self) -> u32 {
        self.config.load().notification.telegram.rate_limit_max_messages
    }

    fn rate_limit_window_secs(&self) -> u32 {
        self.config.load().notification.telegram.rate_limit_window_secs
    }

    fn check_rate_limit(&self) -> bool {
        let max_messages = self.rate_limit_max_messages();
        if max_messages == 0 {
            return false;
        }
        let window_secs = self.rate_limit_window_secs().max(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        loop {
            let cur = self.rate_state.load(Ordering::Acquire);
            let count = cur as u32;
            let window = (cur >> 32) as u32;

            let (next_count, next_window) = if now.saturating_sub(window) >= window_secs {
                (1u32, now)
            } else if count >= max_messages {
                return false;
            } else {
                (count + 1, window)
            };

            let new = ((next_window as u64) << 32) | next_count as u64;
            if self
                .rate_state
                .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    async fn send_message(&self, bot_token: &str, chat_id: &str, text: &str) -> Result<(), Error> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let max_retries = self.config.load().notification.telegram.max_retries;

        let mut attempt = 0;
        loop {
            let resp = self
                .client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                }))
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        NotificationError::Timeout
                    } else {
                        NotificationError::TelegramRequestFailed(e.without_url())
                    }
                })?;

            let status = resp.status();

            if status.is_success() {
                return Ok(());
            }

            if status.as_u16() == 401 || status.as_u16() == 403 {
                let body = response_body(resp).await?;
                if body.contains("chat not found") || body.contains("CHAT_NOT_FOUND") {
                    return Err(NotificationError::TelegramChatNotFound(chat_id.to_string()).into());
                }
                return Err(NotificationError::TelegramAuthError.into());
            }

            if status.as_u16() == 429 {
                let body = response_body(resp).await?;
                let retry_after = telegram_retry_after(&body)?;

                if attempt < max_retries {
                    attempt += 1;
                    log!(NotificationLog::TelegramRateLimitedRetry(
                        retry_after,
                        attempt,
                        max_retries,
                    ));
                    sleep(Duration::from_secs(retry_after)).await;
                    continue;
                } else {
                    return Err(NotificationError::TelegramRateLimited(retry_after).into());
                }
            }
            let body = response_body(resp).await?;
            Err(NotificationError::TelegramHttpError(status.as_u16(), body))?;
        }
    }

    fn format_alert_message(payload: &AlertPayload) -> String {
        let country_str = payload.country.as_deref().unwrap_or("Unknown");
        let source_ip = telegram_html_escape(&payload.source_ip);
        let dest_ip = telegram_html_escape(&payload.dest_ip);
        let country = telegram_html_escape(country_str);
        let threat_type = telegram_html_escape(&payload.threat_type);
        let action_description = telegram_html_escape(&payload.action_description);
        let ts_formatted = Utc
            .timestamp_opt(payload.timestamp, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| payload.timestamp.to_string());
        let timestamp = telegram_html_escape(&ts_formatted);
        format!(
            "🛡 <b>[NetGuardia] {action}</b>\n\
             Source: <code>{src}</code> ({country})\n\
             Target: <code>{dst}</code>\n\
             Threat: {threat} (confidence: {confidence:.0}%)\n\
             Action: {action_desc}\n\
             Time: {time}",
            action = "Threat Detected",
            src = source_ip,
            dst = dest_ip,
            country = country,
            threat = threat_type,
            confidence = payload.confidence * 100.0,
            action_desc = action_description,
            time = timestamp,
        )
    }
}

fn telegram_html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn response_body(resp: reqwest::Response) -> Result<String, Error> {
    let body = resp
        .text()
        .await
        .map_err(|err| NotificationError::TelegramRequestFailed(err.without_url()))?;
    Ok(body)
}

fn telegram_retry_after(body: &str) -> Result<u64, NotificationError> {
    let body: serde_json::Value = serde_json::from_str(body).map_err(NotificationError::TelegramRequestFailed)?;
    Ok(body
        .get("parameters")
        .and_then(|p| p.get("retry_after"))
        .and_then(|r| r.as_u64())
        .unwrap_or(5))
}

#[async_trait]
impl AlertNotifier for TelegramAdapter {
    async fn send_alert(&self, payload: &AlertPayload) -> Result<(), Error> {
        let (bot_token, chat_id) = match self.get_config().await? {
            Some(config) => config,
            None => {
                log!(NotificationLog::TelegramNotConfiguredSkipped);
                return Ok(());
            }
        };

        if !self.check_rate_limit() {
            log!(NotificationLog::TelegramLocalRateLimitDropped(
                self.rate_limit_max_messages(),
                self.rate_limit_window_secs(),
                payload.source_ip.clone(),
            ));
            return Ok(());
        }

        let message = Self::format_alert_message(payload);
        self.send_message(&bot_token, &chat_id, &message).await
    }

    async fn send_test_message(&self) -> Result<(), Error> {
        let (bot_token, chat_id) = match self.get_config().await? {
            Some(config) => config,
            None => Err(NotificationError::NotConfigured("telegram"))?,
        };

        self.send_message(
            &bot_token,
            &chat_id,
            "✅ <b>NetGuardia connected successfully</b>\n\nTelegram notifications are working.",
        )
        .await
    }
}

pub struct TelegramAdapterFactory {
    notif: Arc<dyn ConfigRepo + Send + Sync>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl TelegramAdapterFactory {
    pub fn new(
        notif: Arc<dyn ConfigRepo + Send + Sync>,
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Self {
        Self { notif, config, secrets }
    }
}

impl AlertNotifierFactory for TelegramAdapterFactory {
    fn create(&self) -> Result<Arc<dyn AlertNotifier>, Error> {
        let adapter = TelegramAdapter::new(self.notif.clone(), self.config.clone(), self.secrets.clone())?;
        Ok(Arc::new(adapter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_reads_telegram_parameter() {
        let retry_after = telegram_retry_after(r#"{"parameters":{"retry_after":17}}"#).unwrap();
        assert_eq!(retry_after, 17);
    }

    #[test]
    fn retry_after_defaults_when_parameter_missing() {
        let retry_after = telegram_retry_after(r#"{"ok":false}"#).unwrap();
        assert_eq!(retry_after, 5);
    }

    #[test]
    fn retry_after_rejects_malformed_json() {
        let err = telegram_retry_after("not json").unwrap_err();
        assert!(matches!(err, NotificationError::TelegramRequestFailed { .. }));
    }

    #[test]
    fn alert_message_escapes_telegram_html_fields() {
        let payload = AlertPayload {
            source_ip: "10.0.0.1<script>".to_string(),
            dest_ip: "192.0.2.1&x".to_string(),
            country: Some("US<CA>".to_string()),
            threat_type: "\"><b>owned</b>".to_string(),
            confidence: 0.9,
            action_description: "blocked <now> & notified".to_string(),
            timestamp: 1778284800,
        };

        let message = TelegramAdapter::format_alert_message(&payload);

        assert!(!message.contains("<script>"));
        assert!(!message.contains("<b>owned</b>"));
        assert!(!message.contains("blocked <now>"));
        assert!(message.contains("10.0.0.1&lt;script&gt;"));
        assert!(message.contains("192.0.2.1&amp;x"));
        assert!(message.contains("&quot;&gt;&lt;b&gt;owned&lt;/b&gt;"));
    }
}
