use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{Local, Weekday};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use macros::log;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::{self, Duration};

use super::email_report as report;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::notification::SmtpConfig;
use crate::domain::common::error::Error;
use crate::domain::common::error::notification::NotificationError;
use crate::domain::common::log::system::SystemLog;
use crate::interface::port::secret_store::SecretStorePort;
use crate::interface::port::setting::SettingRepo;

pub struct SmtpClient {
    host: String,
    port: u16,
    username: String,
    password: String,
    /// The sender email address. Falls back to `username` if not set.
    sender: String,
}

impl SmtpClient {
    pub fn from_config(cfg: &SmtpConfig, secrets: Option<&dyn SecretStorePort>) -> Result<Option<Self>, Error> {
        if cfg.host.is_empty() || cfg.username.is_empty() {
            return Ok(None);
        }

        let password = match secrets.and_then(|ss| ss.get_secret("smtp_password").ok().flatten()) {
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

    /// Send an HTML email using the configured SMTP transport.
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
            465 => {
                // Implicit TLS (SMTPS)
                SmtpTransport::relay(&self.host)
                    .map_err(NotificationError::SmtpConnectionFailed)?
                    .port(self.port)
                    .credentials(creds)
                    .build()
            }
            25 | 587 => {
                // STARTTLS (standard submission ports)
                SmtpTransport::starttls_relay(&self.host)
                    .map_err(NotificationError::SmtpConnectionFailed)?
                    .port(self.port)
                    .credentials(creds)
                    .build()
            }
            _ => {
                // Non-standard port — use unencrypted transport with credentials
                SmtpTransport::builder_dangerous(&self.host)
                    .port(self.port)
                    .credentials(creds)
                    .build()
            }
        };

        mailer.send(&email).map_err(NotificationError::SmtpSendFailed)?;

        Ok(())
    }
}

pub struct ReportScheduler {
    db: Arc<dyn SettingRepo + Send + Sync>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl ReportScheduler {
    pub fn new(
        db: Arc<dyn SettingRepo + Send + Sync>,
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Option<Arc<dyn SecretStorePort>>,
    ) -> Self {
        Self { db, config, secrets }
    }

    /// Spawn a background tokio task that runs the weekly check loop.
    pub fn run(&self) -> JoinHandle<()> {
        let db = Arc::clone(&self.db);
        let config = Arc::clone(&self.config);
        let secrets = self.secrets.clone();
        tokio::spawn(async move {
            log!(SystemLog::WeeklyReportSchedulerStarted);
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;

                if !is_send_window() {
                    continue;
                }

                log!(SystemLog::WeeklyReportWindowReached);

                let smtp_cfg = config.load().notification.smtp.clone();

                let smtp = match SmtpClient::from_config(&smtp_cfg, secrets.as_deref()) {
                    Ok(Some(client)) => client,
                    Ok(None) => {
                        log!(SystemLog::SmtpNotConfigured);
                        continue;
                    }
                    Err(e) => {
                        log!(SystemLog::SmtpSettingsReadFailed(e.to_string()));
                        continue;
                    }
                };

                let recipient = smtp_cfg.recipient;
                if recipient.is_empty() {
                    log!(SystemLog::SmtpRecipientMissing);
                    continue;
                }

                let html = match report::generate_weekly_report(&*db) {
                    Ok(h) => h,
                    Err(e) => {
                        log!(SystemLog::WeeklyReportGenerationFailed(e.to_string()));
                        continue;
                    }
                };

                let subject = format!("NetGuardia Weekly Report — {}", Local::now().format("%Y-%m-%d"));
                let send_result = spawn_blocking(move || smtp.send(&recipient, &subject, &html)).await;

                match send_result {
                    Ok(Ok(())) => log!(SystemLog::WeeklyReportSent),
                    Ok(Err(e)) => log!(SystemLog::WeeklyReportSendFailed(e.to_string())),
                    Err(e) => log!(SystemLog::WeeklyReportSendPanicked(e.to_string())),
                }
            }
        })
    }
}

/// Returns `true` when the current local time falls within the Monday 08:00
/// hour (i.e. Monday, hour == 8).
fn is_send_window() -> bool {
    use chrono::{Datelike, Timelike};
    let now = Local::now();
    now.weekday() == Weekday::Mon && now.hour() == 8
}
