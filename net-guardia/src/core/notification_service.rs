use std::sync::Arc;

use crate::adapter::persistence::Database;
use crate::interface::port::notification::AlertNotifier;
use crate::interface::port::repository::RepositoryPort;
use crate::model::error::Error;
use crate::model::error::misc::MiscError;

/// Domain service for notification config (Telegram, SMTP).
/// Coordinates DB persistence and external service testing.
pub struct NotificationService {
    db: Arc<Database>,
}

impl NotificationService {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Get Telegram config with redacted bot_token.
    pub fn get_telegram_config(&self) -> Result<serde_json::Value, Error> {
        match self.db.get_notification_config("telegram")? {
            Some(json_str) => {
                match serde_json::from_str::<serde_json::Value>(&json_str) {
                    Ok(mut config) => {
                        if let Some(token) = config.get("bot_token").and_then(|t| t.as_str())
                            && token.len() > 8 {
                                let redacted = format!("{}...{}", &token[..4], &token[token.len()-4..]);
                                config["bot_token_redacted"] = serde_json::Value::String(redacted);
                                config.as_object_mut().map(|obj| obj.remove("bot_token"));
                            }
                        config["configured"] = serde_json::Value::Bool(true);
                        Ok(config)
                    }
                    Err(_) => Ok(serde_json::json!({"configured": false})),
                }
            }
            None => Ok(serde_json::json!({"configured": false})),
        }
    }

    /// Save Telegram bot_token + chat_id to DB.
    pub fn set_telegram_config(&self, bot_token: &str, chat_id: &str) -> Result<(), Error> {
        let config_json = serde_json::json!({
            "bot_token": bot_token,
            "chat_id": chat_id,
        }).to_string();
        self.db.set_notification_config("telegram", &config_json)
    }

    /// Send a test Telegram message using current config.
    pub async fn test_telegram(&self) -> Result<(), Error> {
        let adapter = crate::adapter::telegram::TelegramAdapter::new(self.db.clone())?;
        adapter.send_test_message().await
    }

    /// Send a test email using current SMTP config.
    pub fn test_smtp(&self) -> Result<String, Error> {
        let smtp_client = crate::core::email::scheduler::SmtpClient::from_database(
            self.db.as_ref() as &dyn RepositoryPort,
        )?;
        let smtp = smtp_client.ok_or_else(|| {
            MiscError::ValidationError { message:
                "SMTP not configured. Set smtp_host, smtp_port, smtp_username, smtp_password first.".into()
            }
        })?;

        let recipient = self.db.get_setting("smtp_recipient")?
            .filter(|r| !r.is_empty())
            .ok_or_else(|| {
                MiscError::ValidationError { message:
                    "No smtp_recipient configured.".into()
                }
            })?;

        smtp.send(
            &recipient,
            "NetGuardia SMTP Test",
            "<h3>NetGuardia SMTP Test</h3><p>If you see this email, SMTP is configured correctly.</p>",
        )?;

        Ok(format!("Test email sent to {}", recipient))
    }
}
