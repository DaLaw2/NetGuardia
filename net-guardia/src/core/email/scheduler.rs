use crate::interface::port::repository::RepositoryPort;
use crate::model::error::database::DatabaseError;
use crate::model::error::Error;
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
}

impl SmtpClient {
    /// Try to construct an `SmtpClient` from Database settings.
    ///
    /// Returns `None` if any required setting (`smtp_host`, `smtp_port`,
    /// `smtp_username`, `smtp_password`) is missing.
    pub fn from_database(db: &dyn RepositoryPort) -> Result<Option<Self>, Error> {
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
        let password = match db.get_setting("smtp_password")? {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };

        let port: u16 = port_str.parse().unwrap_or(587);

        Ok(Some(Self {
            host,
            port,
            username,
            password,
        }))
    }

    /// Send an HTML email using the configured SMTP transport.
    pub fn send(&self, to: &str, subject: &str, html_body: &str) -> Result<(), Error> {
        let from_addr = self.username.parse().map_err(|e| {
            Error::Database(DatabaseError::QueryFailed {
                reason: format!("invalid from address: {e}"),
            })
        })?;
        let to_addr = to.parse().map_err(|e| {
            Error::Database(DatabaseError::QueryFailed {
                reason: format!("invalid to address: {e}"),
            })
        })?;

        let email = Message::builder()
            .from(from_addr)
            .to(to_addr)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| {
                Error::Database(DatabaseError::QueryFailed {
                    reason: format!("failed to build email: {e}"),
                })
            })?;

        let creds = Credentials::new(self.username.clone(), self.password.clone());

        let mailer = SmtpTransport::starttls_relay(&self.host)
            .map_err(|e| {
                Error::Database(DatabaseError::QueryFailed {
                    reason: format!("SMTP relay error: {e}"),
                })
            })?
            .port(self.port)
            .credentials(creds)
            .build();

        mailer.send(&email).map_err(|e| {
            Error::Database(DatabaseError::QueryFailed {
                reason: format!("SMTP send error: {e}"),
            })
        })?;

        Ok(())
    }
}

/// Scheduler that checks once per hour whether it is time to send the weekly
/// report (Monday 08:00 local time) and dispatches it via SMTP.
pub struct ReportScheduler {
    db: Arc<dyn RepositoryPort>,
}

impl ReportScheduler {
    pub fn new(db: Arc<dyn RepositoryPort>) -> Self {
        Self { db }
    }

    /// Spawn a background tokio task that runs the weekly check loop.
    pub fn run(&self) -> tokio::task::JoinHandle<()> {
        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            info!("Weekly report scheduler started");
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;

                if !is_send_window() {
                    continue;
                }

                info!("Weekly report window reached — preparing report");

                let smtp = match SmtpClient::from_database(&*db) {
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

                let subject = format!(
                    "NetGuardia Weekly Report — {}",
                    chrono::Local::now().format("%Y-%m-%d")
                );
                let send_result =
                    tokio::task::spawn_blocking(move || smtp.send(&recipient, &subject, &html))
                        .await;

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
    let now = chrono::Local::now();
    now.format("%A").to_string() == "Monday" && now.format("%H").to_string() == "08"
}
