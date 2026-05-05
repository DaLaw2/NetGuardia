use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{Local, Weekday};
use macros::log;
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::{self, Duration};

use super::email_report as report;
use crate::domain::common::config::AppConfig;
use crate::domain::common::log::system::SystemLog;
use crate::interface::email_sender::EmailSenderFactory;
use crate::interface::report_snapshot::ReportSnapshotRepo;
use crate::interface::secret_store::SecretStorePort;

pub struct ReportScheduler {
    db: Arc<dyn ReportSnapshotRepo>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    email_sender_factory: Arc<dyn EmailSenderFactory>,
}

impl ReportScheduler {
    pub fn new(
        db: Arc<dyn ReportSnapshotRepo>,
        config: Arc<ArcSwap<AppConfig>>,
        secrets: Option<Arc<dyn SecretStorePort>>,
        email_sender_factory: Arc<dyn EmailSenderFactory>,
    ) -> Self {
        Self {
            db,
            config,
            secrets,
            email_sender_factory,
        }
    }

    /// Spawn a background tokio task that runs the weekly check loop.
    pub fn run(&self) -> JoinHandle<()> {
        let db = Arc::clone(&self.db);
        let config = Arc::clone(&self.config);
        let secrets = self.secrets.clone();
        let email_sender_factory = Arc::clone(&self.email_sender_factory);
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

                let smtp = match email_sender_factory
                    .build_smtp_sender(&smtp_cfg, secrets.as_deref())
                    .await
                {
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

                let html = match report::generate_weekly_report(&*db).await {
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
