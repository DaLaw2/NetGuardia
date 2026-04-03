use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use reqwest::Client;
use tracing::{debug, warn};

use crate::interface::port::notification::{AlertNotifier, AlertPayload, NotificationConfigPort};
use crate::interface::port::repository::RepositoryPort;
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::config::constants::TELEGRAM_MAX_RETRIES;
use crate::model::error::Error;
use crate::model::error::notification::NotificationError;

/// Telegram Bot API adapter implementing AlertNotifier.
pub struct TelegramAdapter {
    client: Client,
    notif: Arc<dyn NotificationConfigPort>,
    repo: Arc<dyn RepositoryPort>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    /// Rate limiter: (count, window_start)
    rate_state: Mutex<(u32, Instant)>,
}

impl TelegramAdapter {
    pub fn new(
        notif: Arc<dyn NotificationConfigPort>,
        repo: Arc<dyn RepositoryPort>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| NotificationError::TelegramApiError {
                reason: format!("Failed to create HTTP client: {}", e),
            })?;

        Ok(Self {
            client,
            notif,
            repo,
            secrets,
            rate_state: Mutex::new((0, Instant::now())),
        })
    }

    /// Get bot token and chat ID from DB. Returns None if not configured.
    /// If the bot_token in JSON is `"__encrypted__"`, reads from the secret store.
    fn get_config(&self) -> Result<Option<(String, String)>, Error> {
        match self.notif.get_notification_config("telegram")? {
            Some(json_str) => {
                let config: serde_json::Value =
                    serde_json::from_str(&json_str).map_err(|e| NotificationError::TelegramApiError {
                        reason: format!("Invalid telegram config JSON: {}", e),
                    })?;
                let mut token = config.get("bot_token").and_then(|v| v.as_str()).map(|s| s.to_string());
                let chat_id = config.get("chat_id").and_then(|v| v.as_str()).map(|s| s.to_string());

                // If token is the encrypted sentinel, resolve from secret store
                if token.as_deref() == Some("__encrypted__") {
                    token = self
                        .secrets
                        .as_ref()
                        .and_then(|ss| ss.get_secret("telegram_bot_token").ok().flatten());
                }

                match (token, chat_id) {
                    (Some(t), Some(c)) if !t.is_empty() && !c.is_empty() => Ok(Some((t, c))),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    /// Check rate limit. Returns true if send is allowed.
    fn check_rate_limit(&self) -> bool {
        let mut state = self.rate_state.lock();
        let (count, window_start) = &mut *state;

        // Reset window if >60s has passed
        if window_start.elapsed() > Duration::from_secs(60) {
            *count = 0;
            *window_start = Instant::now();
        }

        let max_per_min: u32 = self
            .repo
            .get_setting("telegram_max_messages_per_minute")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        if *count >= max_per_min {
            return false;
        }

        *count += 1;
        true
    }

    /// Send a message via Telegram Bot API with retry on 429.
    async fn send_message(&self, bot_token: &str, chat_id: &str, text: &str) -> Result<(), Error> {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);

        for attempt in 0..=TELEGRAM_MAX_RETRIES {
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
                        NotificationError::TelegramApiError { reason: e.to_string() }
                    }
                })?;

            let status = resp.status();

            if status.is_success() {
                return Ok(());
            }

            if status.as_u16() == 401 || status.as_u16() == 403 {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("chat not found") || body.contains("CHAT_NOT_FOUND") {
                    return Err(NotificationError::TelegramChatNotFound {
                        chat_id: chat_id.to_string(),
                    }
                    .into());
                }
                return Err(NotificationError::TelegramAuthError.into());
            }

            if status.as_u16() == 429 {
                // Rate limited by Telegram
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let retry_after = body
                    .get("parameters")
                    .and_then(|p| p.get("retry_after"))
                    .and_then(|r| r.as_u64())
                    .unwrap_or(5);

                if attempt < TELEGRAM_MAX_RETRIES {
                    warn!(
                        "Telegram rate limited, retrying after {}s (attempt {}/{})",
                        retry_after,
                        attempt + 1,
                        TELEGRAM_MAX_RETRIES
                    );
                    tokio::time::sleep(Duration::from_secs(retry_after)).await;
                    continue;
                } else {
                    return Err(NotificationError::TelegramRateLimited {
                        retry_after_secs: retry_after,
                    }
                    .into());
                }
            }

            // Other error
            let body = resp.text().await.unwrap_or_default();
            return Err(NotificationError::TelegramApiError {
                reason: format!("HTTP {}: {}", status, body),
            }
            .into());
        }

        unreachable!()
    }

    /// Format alert payload into Telegram message using the system template.
    fn format_alert_message(payload: &AlertPayload) -> String {
        let country_str = payload.country.as_deref().unwrap_or("Unknown");
        format!(
            "🛡 <b>[NetGuardia] {action}</b>\n\
             Source: <code>{src}</code> ({country})\n\
             Target: <code>{dst}</code>\n\
             Threat: {threat} (confidence: {confidence:.0}%)\n\
             Action: {action_desc}\n\
             Time: {time}",
            action = "Threat Detected",
            src = payload.source_ip,
            dst = payload.dest_ip,
            country = country_str,
            threat = payload.threat_type,
            confidence = payload.confidence * 100.0,
            action_desc = payload.action_description,
            time = payload.timestamp,
        )
    }
}

#[async_trait]
impl AlertNotifier for TelegramAdapter {
    async fn send_alert(&self, payload: &AlertPayload) -> Result<(), Error> {
        let (bot_token, chat_id) = match self.get_config()? {
            Some(config) => config,
            None => {
                debug!("Telegram not configured, skipping alert");
                return Ok(());
            }
        };

        if !self.check_rate_limit() {
            let max_per_min: u32 = self
                .repo
                .get_setting("telegram_max_messages_per_minute")
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20);
            warn!(
                "Telegram rate limit reached ({}/min), dropping alert for IP {}",
                max_per_min, payload.source_ip
            );
            return Ok(());
        }

        let message = Self::format_alert_message(payload);
        self.send_message(&bot_token, &chat_id, &message).await
    }

    async fn send_test_message(&self) -> Result<(), Error> {
        let (bot_token, chat_id) = match self.get_config()? {
            Some(config) => config,
            None => {
                return Err(NotificationError::NotConfigured {
                    channel: "telegram".to_string(),
                }
                .into());
            }
        };

        self.send_message(
            &bot_token,
            &chat_id,
            "✅ <b>NetGuardia connected successfully</b>\n\nTelegram notifications are working.",
        )
        .await
    }
}
