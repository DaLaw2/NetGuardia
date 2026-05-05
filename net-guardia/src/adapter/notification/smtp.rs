use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

use crate::domain::common::config::notification::SmtpConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::notification::NotificationError;
use crate::interface::email_sender::{EmailSender, EmailSenderFactory};
use crate::interface::secret_store::SecretStorePort;

pub struct SmtpClient {
    host: String,
    port: u16,
    username: String,
    password: String,
    sender: String,
}

impl SmtpClient {
    pub async fn from_config(cfg: &SmtpConfig, secrets: Option<&dyn SecretStorePort>) -> Result<Option<Self>, Error> {
        if cfg.host.is_empty() || cfg.username.is_empty() {
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

        let sender = if cfg.sender.is_empty() {
            cfg.username.clone()
        } else {
            cfg.sender.clone()
        };

        if !sender.contains('@') {
            return Ok(None);
        }

        Ok(Some(Self {
            host: cfg.host.clone(),
            port: cfg.port,
            username: cfg.username.clone(),
            password,
            sender,
        }))
    }

    pub fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error> {
        let from_addr = self
            .sender
            .parse()
            .map_err(|e| NotificationError::InvalidAddress("from", e))?;
        let to_addr = to.parse().map_err(|e| NotificationError::InvalidAddress("to", e))?;

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
