use crate::interface::port::repository::RepositoryPort;
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::error::Error;
use crate::model::error::notification::NotificationError;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{error, info, warn};

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
    /// If a `SecretStorePort` is provided, reads the password from the secret store
    /// (falling back to the settings table for backward compat before migration).
    pub fn from_database(
        db: &dyn RepositoryPort,
        secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<Self>, Error> {
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

        // Try secret store first, fall back to settings
        let password = Self::resolve_smtp_password(db, secrets)?;
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

    /// Try to construct an `SmtpClient` from a SOAR port (which also provides `get_setting`).
    /// Same logic as `from_database`, but accepts `&dyn SoarPort` instead of `&dyn RepositoryPort`.
    pub fn from_soar_port(
        db: &dyn crate::interface::port::soar::SoarPort,
        secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<Self>, Error> {
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

        // Try secret store first, fall back to settings via SoarPort
        let password = match secrets.and_then(|ss| ss.get_secret("smtp_password").ok().flatten()) {
            Some(pw) if !pw.is_empty() => pw,
            _ => match db.get_setting("smtp_password")? {
                Some(v) if !v.is_empty() && v != "__encrypted__" => v,
                _ => return Ok(None),
            },
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
    fn resolve_smtp_password(
        db: &dyn RepositoryPort,
        secrets: Option<&dyn SecretStorePort>,
    ) -> Result<Option<String>, Error> {
        if let Some(ss) = secrets
            && let Some(pw) = ss.get_secret("smtp_password")?
            && !pw.is_empty()
        {
            return Ok(Some(pw));
        }
        // Fallback: read from settings (pre-migration or no secret store)
        let val = db.get_setting("smtp_password")?;
        match val {
            Some(ref v) if v == "__encrypted__" => Ok(None),
            other => Ok(other),
        }
    }

    /// Send an HTML email using the configured SMTP transport.
    pub fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error> {
        let from_addr = self.sender.parse().map_err(|e| NotificationError::InvalidAddress {
            reason: format!("invalid from address: {e}"),
        })?;
        let to_addr = to.parse().map_err(|e| NotificationError::InvalidAddress {
            reason: format!("invalid to address: {e}"),
        })?;

        let email = Message::builder()
            .from(from_addr)
            .to(to_addr)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| NotificationError::MessageBuildFailed { reason: e.to_string() })?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = match self.port {
            465 => {
                // Implicit TLS (SMTPS)
                SmtpTransport::relay(&self.host)
                    .map_err(|e| NotificationError::SmtpConnectionFailed { reason: e.to_string() })?
                    .port(self.port)
                    .credentials(creds)
                    .build()
            }
            25 | 587 => {
                // STARTTLS (standard submission ports)
                SmtpTransport::starttls_relay(&self.host)
                    .map_err(|e| NotificationError::SmtpConnectionFailed { reason: e.to_string() })?
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

        mailer
            .send(&email)
            .map_err(|e| NotificationError::SmtpSendFailed { reason: e.to_string() })?;

        Ok(())
    }
}

/// Scheduler that checks once per hour whether it is time to send the weekly
/// report (Monday 08:00 local time) and dispatches it via SMTP.
pub struct ReportScheduler {
    db: Arc<dyn RepositoryPort>,
    secrets: Option<Arc<dyn SecretStorePort>>,
}

impl ReportScheduler {
    pub fn new(db: Arc<dyn RepositoryPort>, secrets: Option<Arc<dyn SecretStorePort>>) -> Self {
        Self { db, secrets }
    }

    /// Spawn a background tokio task that runs the weekly check loop.
    pub fn run(&self) -> tokio::task::JoinHandle<()> {
        let db = Arc::clone(&self.db);
        let secrets = self.secrets.clone();
        tokio::spawn(async move {
            info!("Weekly report scheduler started");
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;

                if !is_send_window() {
                    continue;
                }

                info!("Weekly report window reached — preparing report");

                let smtp = match SmtpClient::from_database(&*db, secrets.as_deref()) {
                    Ok(Some(client)) => client,
                    Ok(None) => {
                        warn!(
                            "SMTP is not configured (missing smtp_host/port/username/password). \
                             Skipping weekly report."
                        );
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to read SMTP settings: {e}");
                        continue;
                    }
                };

                let recipient = match db.get_setting("smtp_recipient") {
                    Ok(Some(r)) if !r.is_empty() => r,
                    _ => {
                        warn!("No smtp_recipient configured. Skipping weekly report.");
                        continue;
                    }
                };

                let html = match super::report::generate_weekly_report(&*db) {
                    Ok(h) => h,
                    Err(e) => {
                        error!("Failed to generate weekly report: {e}");
                        continue;
                    }
                };

                let subject = format!("NetGuardia Weekly Report — {}", chrono::Local::now().format("%Y-%m-%d"));
                let send_result = tokio::task::spawn_blocking(move || smtp.send(&recipient, &subject, &html)).await;

                match send_result {
                    Ok(Ok(())) => info!("Weekly report sent successfully"),
                    Ok(Err(e)) => error!("Failed to send weekly report: {e}"),
                    Err(e) => error!("Send task panicked: {e}"),
                }
            }
        })
    }
}

/// Returns `true` when the current local time falls within the Monday 08:00
/// hour (i.e. Monday, hour == 8).
fn is_send_window() -> bool {
    use chrono::{Datelike, Timelike};
    let now = chrono::Local::now();
    now.weekday() == chrono::Weekday::Mon && now.hour() == 8
}
