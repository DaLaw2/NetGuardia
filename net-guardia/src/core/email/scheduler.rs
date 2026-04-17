use std::sync::Arc;

use chrono::{Local, Weekday};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use macros::log;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::{self, Duration};

use super::report;
use crate::interface::port::secret_store::SecretStorePort;
use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;
use crate::model::error::notification::NotificationError;
use crate::model::log::system::SystemLog;

/// SMTP client wrapper that builds a `lettre::SmtpTransport` from Database
/// settings and sends an email.
pub struct SmtpClient {
    host: String,
    port: u16,
    username: String,
    password: String,
    /// The sender email address. Falls back to `username` if not set.
    sender: String,
}

impl SmtpClient {
    /// Try to construct an `SmtpClient` from Database settings.
    ///
    /// Returns `None` if any required setting (`smtp_host`, `smtp_port`,
    /// `smtp_username`, `smtp_password`) is missing.
    /// If a `SecretStorePort` is provided, reads the password from the secret store.
    pub fn from_database(db: &dyn SettingRepo, secrets: Option<&dyn SecretStorePort>) -> Result<Option<Self>, Error> {
        let host = match db.get_setting("smtp_host")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let port_str = match db.get_setting("smtp_port")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let username = match db.get_setting("smtp_username")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let password = Self::resolve_smtp_password(secrets)?;
        let password = match password {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let port: u16 = port_str.parse().unwrap_or(587);

        // smtp_sender overrides username as the From address.
        // Fall back to username if smtp_sender is not configured.
        let sender = match db.get_setting("smtp_sender")? {
            Some(v) if !v.is_empty() => v,
            _ => username.clone(),
        };

        // Validate that the sender looks like an email address
        if !sender.contains('@') {
            return Ok(None);
        }

        Ok(Some(Self {
            host,
            port,
            username,
            password,
            sender,
        }))
    }

    /// Try to construct an `SmtpClient` from any SettingRepo implementation.
    /// Kept as a separate method name for call-site clarity (SOAR actions).
    pub fn from_soar_port(db: &dyn SettingRepo, secrets: Option<&dyn SecretStorePort>) -> Result<Option<Self>, Error> {
        let host = match db.get_setting("smtp_host")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let port_str = match db.get_setting("smtp_port")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let username = match db.get_setting("smtp_username")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let password = match secrets.and_then(|ss| ss.get_secret("smtp_password").ok().flatten()) {
            Some(pw) if !pw.is_empty() => pw,
            _ => return Ok(None),
        };

        let port: u16 = port_str.parse().unwrap_or(587);

        let sender = match db.get_setting("smtp_sender")? {
            Some(v) if !v.is_empty() => v,
            _ => username.clone(),
        };

        if !sender.contains('@') {
            return Ok(None);
        }

        Ok(Some(Self {
            host,
            port,
            username,
            password,
            sender,
        }))
    }

    /// Resolve SMTP password: try secret store first, fall back to settings.
    fn resolve_smtp_password(secrets: Option<&dyn SecretStorePort>) -> Result<Option<String>, Error> {
        match secrets {
            Some(ss) => Ok(ss.get_secret("smtp_password")?.filter(|pw| !pw.is_empty())),
            None => Ok(None),
        }
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

/// Scheduler that checks once per hour whether it is time to send the weekly
/// report (Monday 08:00 local time) and dispatches it via SMTP.
pub struct ReportScheduler {
    db: Arc<dyn SettingRepo>,
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl ReportScheduler {
    pub fn new(db: Arc<dyn SettingRepo>, secrets: Option<Arc<dyn SecretStorePort>>) -> Self {
        Self { db, secrets }
    }

    /// Spawn a background tokio task that runs the weekly check loop.
    pub fn run(&self) -> JoinHandle<()> {
        let db = Arc::clone(&self.db);
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

                let smtp = match SmtpClient::from_database(&*db, secrets.as_deref()) {
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

                let recipient = match db.get_setting("smtp_recipient") {
                    Ok(Some(r)) if !r.is_empty() => r,
                    _ => {
                        log!(SystemLog::SmtpRecipientMissing);
                        continue;
                    }
                };

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
