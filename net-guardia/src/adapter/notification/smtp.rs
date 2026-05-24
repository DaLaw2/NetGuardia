use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::common::error::Error;
use crate::common::error::notification::NotificationError;
use crate::domain::common::config::notification::SmtpConfig;
use crate::interface::reporting::email_sender::{EmailSender, EmailSenderFactory};
use crate::interface::system::secret_store::SecretStorePort;

pub struct SmtpClient {
    host: String,
    port: u16,
    username: String,
    password: String,
    sender: String,
}

impl SmtpClient {
    pub async fn from_config(cfg: &SmtpConfig, secrets: Option<&dyn SecretStorePort>) -> Result<Option<Self>, Error> {
        let host = cfg.host.trim();
        let username = cfg.username.trim();
        if host.is_empty() || username.is_empty() {
            return Ok(None);
        }

        let sender = if cfg.sender.trim().is_empty() {
            username.to_string()
        } else {
            cfg.sender.trim().to_string()
        };

        if !sender.contains('@') {
            return Ok(None);
        }

        let secret = match secrets {
            Some(ss) => ss.get_secret("smtp_password").await?,
            None => None,
        };
        let password = match secret {
            Some(pw) if !pw.is_empty() => pw,
            _ => return Ok(None),
        };

        Ok(Some(Self {
            host: host.to_string(),
            port: cfg.port,
            username: username.to_string(),
            password,
            sender,
        }))
    }

    pub fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error> {
        let from_addr = parse_email_address("from", &self.sender)?;
        let to_addr = parse_email_address("to", to)?;

        let email = Message::builder()
            .from(from_addr)
            .to(to_addr)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(NotificationError::MessageBuildFailed)?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = match self.port {
            465 => SmtpTransport::relay(&self.host)
                .map_err(NotificationError::SmtpConnectionFailed)?
                .port(self.port)
                .credentials(creds)
                .build(),
            25 | 587 => SmtpTransport::starttls_relay(&self.host)
                .map_err(NotificationError::SmtpConnectionFailed)?
                .port(self.port)
                .credentials(creds)
                .build(),
            _ => SmtpTransport::builder_dangerous(&self.host)
                .port(self.port)
                .credentials(creds)
                .build(),
        };

        mailer.send(&email).map_err(NotificationError::SmtpSendFailed)?;

        Ok(())
    }
}

fn parse_email_address(field: &'static str, value: &str) -> Result<Mailbox, Error> {
    value
        .trim()
        .parse()
        .map_err(|e| NotificationError::InvalidAddress(field, e).into())
}

impl EmailSender for SmtpClient {
    fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error> {
        self.send(to, subject, html_body)
    }
}

pub struct SmtpClientFactory;

#[async_trait::async_trait]
impl EmailSenderFactory for SmtpClientFactory {
    async fn build_smtp_sender(
        &self,
        cfg: &SmtpConfig,
        secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<Box<dyn EmailSender>>, Error> {
        SmtpClient::from_config(cfg, secrets)
            .await
            .map(|opt| opt.map(|c| Box::new(c) as Box<dyn EmailSender>))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSecrets;

    #[async_trait::async_trait]
    impl SecretStorePort for FakeSecrets {
        async fn get_secret(&self, key: &str) -> Result<Option<String>, Error> {
            Ok((key == "smtp_password").then(|| " secret with spaces ".to_string()))
        }

        async fn set_secret(&self, _key: &str, _plaintext: &str) -> Result<(), Error> {
            Ok(())
        }

        fn encrypt_envelope(&self, plaintext: &str) -> Result<String, Error> {
            Ok(plaintext.to_string())
        }
    }

    #[tokio::test]
    async fn from_config_trims_non_secret_smtp_fields() {
        let cfg = SmtpConfig {
            host: " smtp.example.test ".to_string(),
            port: 587,
            username: " sender@example.test ".to_string(),
            sender: " alerts@example.test ".to_string(),
            recipient: String::new(),
        };

        let client = SmtpClient::from_config(&cfg, Some(&FakeSecrets))
            .await
            .expect("smtp config")
            .expect("smtp client");

        assert_eq!(client.host, "smtp.example.test");
        assert_eq!(client.username, "sender@example.test");
        assert_eq!(client.sender, "alerts@example.test");
        assert_eq!(client.password, " secret with spaces ");
    }

    #[test]
    fn parse_email_address_trims_recipient_text() {
        let parsed = parse_email_address("to", " security@example.test ").expect("recipient");

        assert_eq!(parsed.email.to_string(), "security@example.test");
    }
}
