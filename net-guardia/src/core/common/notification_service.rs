use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::task::spawn_blocking;

use crate::common::error::Error;
use crate::common::error::notification::NotificationError;
use crate::domain::common::config::AppConfig;
use crate::interface::reporting::email_sender::{EmailSender, EmailSenderFactory};
use crate::interface::response::notification::AlertNotifierFactory;
use crate::interface::system::config_repo::ConfigRepo;
use crate::interface::system::secret_store::SecretStorePort;

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

    pub async fn get_telegram_config(&self) -> Result<serde_json::Value, Error> {
        match self.notif.get_notification_config("telegram").await? {
            Some(json_str) => match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(mut config) => {
                    let token = match config.get("bot_token").and_then(|t| t.as_str()) {
                        Some("__encrypted__") => self.secrets.get_secret("telegram_bot_token").await?,
                        Some(t) => Some(t.to_string()),
                        None => None,
                    };

                    if let Some(ref t) = token
                        && let Some(redacted) = redact_secret(t)
                    {
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

    pub async fn set_telegram_config(&self, bot_token: &str, chat_id: &str) -> Result<(), Error> {
        let (bot_token, chat_id) = telegram_config_fields(bot_token, chat_id)?;
        self.secrets.set_secret("telegram_bot_token", bot_token).await?;
        let config_json = serde_json::json!({
            "bot_token": "__encrypted__",
            "chat_id": chat_id,
        })
        .to_string();
        self.notif.set_notification_config("telegram", &config_json).await
    }

    pub async fn test_telegram(&self) -> Result<(), Error> {
        let notifier = self.alert_notifier_factory.create()?;
        notifier.send_test_message().await
    }

    pub async fn test_smtp(&self) -> Result<String, Error> {
        let smtp_cfg = self.config.load().notification.smtp.clone();
        let smtp = self
            .email_sender_factory
            .build_smtp_sender(&smtp_cfg, Some(self.secrets.as_ref()))
            .await?
            .ok_or_else(|| NotificationError::NotConfigured("smtp"))?;

        if smtp_cfg.recipient.is_empty() {
            Err(NotificationError::MissingConfigField("smtp_recipient"))?;
        }
        let recipient = smtp_cfg.recipient;
        send_email_on_blocking_thread(
            smtp,
            recipient.clone(),
            "NetGuardia SMTP Test".to_string(),
            "<h3>NetGuardia SMTP Test</h3><p>If you see this email, SMTP is configured correctly.</p>".to_string(),
        )
        .await?;

        Ok(format!("Test email sent to {recipient}"))
    }
}

fn telegram_config_fields<'a>(bot_token: &'a str, chat_id: &'a str) -> Result<(&'a str, &'a str), Error> {
    let bot_token = bot_token.trim();
    if bot_token.is_empty() {
        Err(NotificationError::MissingConfigField("telegram_bot_token"))?;
    }
    let chat_id = chat_id.trim();
    if chat_id.is_empty() {
        Err(NotificationError::MissingConfigField("telegram_chat_id"))?;
    }
    Ok((bot_token, chat_id))
}

async fn send_email_on_blocking_thread(
    smtp: Box<dyn EmailSender>,
    recipient: String,
    subject: String,
    html_body: String,
) -> Result<(), Error> {
    spawn_blocking(move || smtp.send(&recipient, &subject, &html_body))
        .await
        .map_err(NotificationError::SmtpSendFailed)??;
    Ok(())
}

fn redact_secret(secret: &str) -> Option<String> {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 8 {
        return None;
    }

    let prefix: String = chars.iter().take(4).collect();
    let suffix: String = chars[chars.len() - 4..].iter().collect();
    Some(format!("{prefix}...{suffix}"))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::thread::ThreadId;

    use super::*;

    struct RecordingSender {
        thread_id: Arc<Mutex<Option<ThreadId>>>,
    }

    impl EmailSender for RecordingSender {
        fn send(&self, _to: &str, _subject: &str, _html_body: &str) -> Result<(), Error> {
            if let Ok(mut thread_id) = self.thread_id.lock() {
                *thread_id = Some(thread::current().id());
            }
            Ok(())
        }
    }

    #[test]
    fn redact_secret_uses_character_boundaries() {
        assert_eq!(redact_secret("測試資料ABCD尾端").as_deref(), Some("測試資料...CD尾端"));
    }

    #[test]
    fn redact_secret_skips_short_values() {
        assert_eq!(redact_secret("12345678"), None);
    }

    #[test]
    fn telegram_config_fields_trim_values() {
        let (token, chat_id) = telegram_config_fields(" token ", " chat ").expect("telegram fields");

        assert_eq!(token, "token");
        assert_eq!(chat_id, "chat");
    }

    #[test]
    fn telegram_config_fields_reject_empty_values() {
        for (token, chat_id, expected_field) in [
            ("", "chat", "telegram_bot_token"),
            (" token ", "   ", "telegram_chat_id"),
        ] {
            let err = telegram_config_fields(token, chat_id).expect_err("empty telegram field should fail");
            match err {
                Error::Notification(NotificationError::MissingConfigField { field }) => {
                    assert_eq!(field, expected_field);
                }
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn smtp_test_send_runs_on_blocking_thread() {
        let async_thread_id = thread::current().id();
        let send_thread_id = Arc::new(Mutex::new(None));
        let sender = RecordingSender {
            thread_id: Arc::clone(&send_thread_id),
        };

        send_email_on_blocking_thread(
            Box::new(sender),
            "admin@example.test".to_string(),
            "subject".to_string(),
            "<p>body</p>".to_string(),
        )
        .await
        .expect("send");

        let send_thread_id = send_thread_id.lock().ok().and_then(|thread_id| *thread_id);
        assert!(matches!(send_thread_id, Some(thread_id) if thread_id != async_thread_id));
    }
}
