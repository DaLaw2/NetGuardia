use std::sync::Arc;

use crate::interface::port::notification::{AlertNotifier, NotificationConfigPort};
use crate::interface::port::repository::RepositoryPort;
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;

/// Domain service for notification config (Telegram, SMTP).
/// Coordinates DB persistence and external service testing.
pub struct NotificationService {
    notif: Arc<dyn NotificationConfigPort>,
    repo: Arc<dyn RepositoryPort>,
    secrets: Arc<dyn SecretStorePort>,
}

impl NotificationService {
    pub fn new(
        notif: Arc<dyn NotificationConfigPort>,
        repo: Arc<dyn RepositoryPort>,
        secrets: Arc<dyn SecretStorePort>,
    ) -> Self {
        Self { notif, repo, secrets }
    }

    /// Get Telegram config with redacted bot_token.
    pub fn get_telegram_config(&self) -> Result<serde_json::Value, Error> {
        match self.notif.get_notification_config("telegram")? {
            Some(json_str) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(mut config) => {
                    // Resolve the actual token for redaction display
                    let token = match config.get("bot_token").and_then(|t| t.as_str()) {
                        Some("__encrypted__") => self.secrets.get_secret("telegram_bot_token")?,
                        Some(t) => Some(t.to_string()),
                        None => None,
                    };

                    if let Some(ref t) = token
                        && t.len() > 8
                    {
                        let redacted = format!("{}...{}", &t[..4], &t[t.len() - 4..]);
                        config["bot_token_redacted"] = serde_json::Value::String(redacted);
                    }
                    config.as_object_mut().map(|obj| obj.remove("bot_token"));
                    config["configured"] = serde_json::Value::Bool(true);
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
    pub fn set_telegram_config(&self, bot_token: &str, chat_id: &str) -> Result<(), Error> {
        self.secrets.set_secret("telegram_bot_token", bot_token)?;
        let config_json = serde_json::json!({
            "bot_token": "__encrypted__",
            "chat_id": chat_id,
        })
        .to_string();
        self.notif.set_notification_config("telegram", &config_json)
    }

    /// Send a test Telegram message using current config.
    pub async fn test_telegram(&self) -> Result<(), Error> {
        let adapter = crate::adapter::telegram::TelegramAdapter::new(
            self.notif.clone(),
            self.repo.clone(),
            Some(self.secrets.clone()),
        )?;
        adapter.send_test_message().await
    }

    /// Send a test email using current SMTP config.
    pub fn test_smtp(&self) -> Result<String, Error> {
        let smtp_client =
            crate::core::email::scheduler::SmtpClient::from_database(self.repo.as_ref(), Some(self.secrets.as_ref()))?;
        let smtp = smtp_client.ok_or_else(|| MiscError::ValidationError {
            message: "SMTP not configured. Set smtp_host, smtp_port, smtp_username, smtp_password first. \
                 If smtp_username is not an email address, also set smtp_sender."
                .into(),
        })?;

        let recipient = self
            .repo
            .get_setting("smtp_recipient")?
            .filter(|r| !r.is_empty())
            .ok_or_else(|| MiscError::ValidationError {
                message: "No smtp_recipient configured.".into(),
            })?;

        smtp.send(
            &recipient,
            "NetGuardia SMTP Test",
            "<h3>NetGuardia SMTP Test</h3><p>If you see this email, SMTP is configured correctly.</p>",
        )?;

        Ok(format!("Test email sent to {}", recipient))
    }
}
