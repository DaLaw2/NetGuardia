use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use macros::log;
use reqwest::Client;
use tokio::time::sleep;

use crate::interface::port::app_repo::AppRepo;
use crate::interface::port::notification::{AlertNotifier, AlertNotifierFactory, AlertPayload};
use crate::interface::port::secret_store::SecretStorePort;
use crate::interface::port::setting::SettingRepo;
use crate::model::config::constants::TELEGRAM_MAX_RETRIES;
use crate::model::error::Error;
use crate::model::error::notification::NotificationError;
use crate::model::log::system::SystemLog;

/// Telegram Bot API adapter implementing AlertNotifier.
pub struct TelegramAdapter {
    client: Client,
    notif: Arc<dyn SettingRepo>,
    repo: Arc<dyn AppRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    /// Packed rate-limit state: high 32 bits = window-start unix seconds,
    /// low 32 bits = count consumed in this window. Updated via CAS so the
    /// hot path stays lock-free.
    rate_state: AtomicU64,
}

impl TelegramAdapter {
    pub fn new(
        notif: Arc<dyn SettingRepo>,
        repo: Arc<dyn AppRepo>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Result<Self, Error> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| NotificationError::TelegramRequestFailed(e.without_url()))?;

        Ok(Self {
            client,
            notif,
            repo,
            secrets,
            rate_state: AtomicU64::new(0),
        })
    }

    /// Get bot token and chat ID from DB. Returns None if not configured.
    /// If the bot_token in JSON is `"__encrypted__"`, reads from the secret store.
    fn get_config(&self) -> Result<Option<(String, String)>, Error> {
        match self.notif.get_notification_config("telegram")? {
            Some(json_str) => {
                let config: serde_json::Value =
                    serde_json::from_str(&json_str).map_err(NotificationError::TelegramRequestFailed)?;
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

    /// Read the configured per-window message cap from settings.
    fn rate_limit_max_messages(&self) -> u32 {
        self.repo
            .get_setting("telegram_rate_limit_max_messages")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20)
    }

    /// Read the configured window length (seconds) from settings.
    fn rate_limit_window_secs(&self) -> u32 {
        self.repo
            .get_setting("telegram_rate_limit_window_secs")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
    }

    /// Check rate limit. Returns true if send is allowed.
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
                        // Strip URL — it embeds the bot token in the path
                        // (`/bot<TOKEN>/sendMessage`) and reqwest::Error's
                        // Display includes the full URL by default, which
                        // would leak the token into journal/error logs.
                        NotificationError::TelegramRequestFailed(e.without_url())
                    }
                })?;

            let status = resp.status();

            if status.is_success() {
                return Ok(());
            }

            if status.as_u16() == 401 || status.as_u16() == 403 {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("chat not found") || body.contains("CHAT_NOT_FOUND") {
                    return Err(NotificationError::TelegramChatNotFound(chat_id.to_string()).into());
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
                    log!(SystemLog::TelegramRateLimitedRetry(
                        retry_after,
                        attempt + 1,
                        TELEGRAM_MAX_RETRIES,
                    ));
                    sleep(Duration::from_secs(retry_after)).await;
                    continue;
                } else {
                    return Err(NotificationError::TelegramRateLimited(retry_after).into());
                }
            }

            // Other error
            let body = resp.text().await.unwrap_or_default();
            Err(NotificationError::TelegramHttpError(status.as_u16(), body))?;
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
                log!(SystemLog::TelegramNotConfiguredSkipped);
                return Ok(());
            }
        };

        if !self.check_rate_limit() {
            log!(SystemLog::TelegramLocalRateLimitDropped(
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
        let (bot_token, chat_id) = match self.get_config()? {
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

/// Adapter-side factory that satisfies the `AlertNotifierFactory` port. Holds
/// the same shared dependencies the long-lived adapter uses; each `create()`
/// call instantiates a fresh `TelegramAdapter` so the test path observes
/// whatever config the user just saved.
pub struct TelegramAdapterFactory {
    notif: Arc<dyn SettingRepo>,
    repo: Arc<dyn AppRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl TelegramAdapterFactory {
    pub fn new(notif: Arc<dyn SettingRepo>, repo: Arc<dyn AppRepo>, secrets: Option<Arc<dyn SecretStorePort>>) -> Self {
        Self { notif, repo, secrets }
    }
}

impl AlertNotifierFactory for TelegramAdapterFactory {
    fn create(&self) -> Result<Arc<dyn AlertNotifier>, Error> {
        let adapter = TelegramAdapter::new(self.notif.clone(), self.repo.clone(), self.secrets.clone())?;
        Ok(Arc::new(adapter))
    }
}
