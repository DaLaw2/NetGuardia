use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::Value;

use crate::domain::common::config::AppConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::misc::MiscError;
use crate::interface::config_repo::ConfigRepo;
use crate::interface::email_sender::EmailSenderFactory;
use crate::interface::notification::AlertNotifierFactory;
use crate::interface::secret_store::SecretStorePort;

/// Domain service for notification config (Telegram, SMTP).
/// Coordinates DB persistence and external service testing.
pub struct NotificationService {
    notif: Arc<dyn ConfigRepo + Send + Sync>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Arc<dyn SecretStorePort>,
    alert_notifier_factory: Arc<dyn AlertNotifierFactory>,
    email_sender_factory: Arc<dyn EmailSenderFactory>,
}

impl NotificationService {
    pub fn new(
        notif: Arc<dyn ConfigRepo + Send + Sync>,
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Arc<dyn SecretStorePort>,
        alert_notifier_factory: Arc<dyn AlertNotifierFactory>,
        email_sender_factory: Arc<dyn EmailSenderFactory>,
    ) -> Self {
        Self {
            notif,
            config,
            secrets,
            alert_notifier_factory,
            email_sender_factory,
        }
    }

    /// Get Telegram config with redacted bot_token.
    pub async fn get_telegram_config(&self) -> Result<serde_json::Value, Error> {
        match self.notif.get_notification_config("telegram").await? {
            Some(json_str) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(mut config) => {
                    // Resolve the actual token for redaction display
                    let token = match config.get("bot_token").and_then(|t| t.as_str()) {
                        Some("__encrypted__") => self.secrets.get_secret("telegram_bot_token").await?,
                        Some(t) => Some(t.to_string()),
                        None => None,
                    };

                    if let Some(ref t) = token
                        && t.len() > 8
                    {
                        let redacted = format!("{}...{}", &t[..4], &t[t.len() - 4..]);
                        config["bot_token_redacted"] = Value::String(redacted);
                    }
                    config.as_object_mut().map(|obj| obj.remove("bot_token"));
                    config["configured"] = Value::Bool(true);
                    Ok(config)
                }
                Err(_) => Ok(serde_json::json!({"configured": false})),
            },
            None => Ok(serde_json::json!({"configured": false})),
        }
    }

    /// Save Telegram bot_token + chat_id to DB.
    /// The bot_token is stored encrypted in the secret store; the config JSON
    /// holds the `"__encrypted__"` sentinel.
    pub async fn set_telegram_config(&self, bot_token: &str, chat_id: &str) -> Result<(), Error> {
        self.secrets.set_secret("telegram_bot_token", bot_token).await?;
        let config_json = serde_json::json!({
            "bot_token": "__encrypted__",
            "chat_id": chat_id,
        })
        .to_string();
        self.notif.set_notification_config("telegram", &config_json).await
    }

    /// Send a test Telegram message using current config. The factory
    /// constructs a fresh notifier on every call so the test reflects the
    /// most-recently-saved config (the user typically clicks "test"
    /// immediately after `set_telegram_config`).
    pub async fn test_telegram(&self) -> Result<(), Error> {
        let notifier = self.alert_notifier_factory.create()?;
        notifier.send_test_message().await
    }

    /// Send a test email using current SMTP config.
    pub async fn test_smtp(&self) -> Result<String, Error> {
        let smtp_cfg = self.config.load().notification.smtp.clone();
        let smtp = self
            .email_sender_factory
            .build_smtp_sender(&smtp_cfg, Some(self.secrets.as_ref()))
            .await?
            .ok_or_else(|| {
                MiscError::ValidationError(
                    "SMTP not configured. Set smtp_host, smtp_port, smtp_username, smtp_password first. \
                     If smtp_username is not an email address, also set smtp_sender.",
                )
            })?;

        if smtp_cfg.recipient.is_empty() {
            Err(MiscError::ValidationError("No smtp_recipient configured."))?;
        }
        let recipient = smtp_cfg.recipient;

        smtp.send(
            &recipient,
            "NetGuardia SMTP Test",
            "<h3>NetGuardia SMTP Test</h3><p>If you see this email, SMTP is configured correctly.</p>",
        )?;

        Ok(format!("Test email sent to {}", recipient))
    }
}
