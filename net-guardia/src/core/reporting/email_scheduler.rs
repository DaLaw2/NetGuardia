use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{DateTime, Datelike, Local, Timelike, Weekday};
use macros::log;
use parking_lot::Mutex;
use tokio::task::spawn_blocking;

use super::email_report;
use crate::common::log::reporting::ReportingLog;
use crate::domain::common::config::AppConfig;
use crate::interface::reporting::email_sender::EmailSenderFactory;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;
use crate::interface::system::secret_store::SecretStorePort;

const LAST_SENT_WEEK_SNAPSHOT_KEY: &str = "weekly_report_last_sent_week";

pub struct ReportScheduler {
    db: Arc<dyn ReportSnapshotRepo>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    email_sender_factory: Arc<dyn EmailSenderFactory>,
    last_sent_week: Mutex<Option<(i32, u32)>>,
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
            last_sent_week: Mutex::new(None),
        }
    }

    pub async fn send_if_due(&self) {
        self.send_if_due_at(Local::now()).await;
    }

    async fn send_if_due_at(&self, now: DateTime<Local>) {
        if !is_send_window(now) {
            return;
        }

        let week = report_week(now);
        if self.already_sent_for_week(week).await {
            return;
        }

        log!(ReportingLog::WeeklyReportWindowReached);

        let smtp_cfg = self.config.load().notification.smtp.clone();

        let smtp = match self
            .email_sender_factory
            .build_smtp_sender(&smtp_cfg, self.secrets.as_deref())
            .await
        {
            Ok(Some(client)) => client,
            Ok(None) => {
                log!(ReportingLog::SmtpNotConfigured);
                return;
            }
            Err(e) => {
                log!(ReportingLog::SmtpSettingsReadFailed(e.to_string()));
                return;
            }
        };

        let recipient = smtp_cfg.recipient;
        if recipient.is_empty() {
            log!(ReportingLog::SmtpRecipientMissing);
            return;
        }

        let html = match email_report::generate_weekly_report(&*self.db).await {
            Ok(h) => h,
            Err(e) => {
                log!(ReportingLog::WeeklyReportGenerationFailed(e.to_string()));
                return;
            }
        };

        let subject = format!("NetGuardia Weekly Report — {}", now.format("%Y-%m-%d"));
        let send_result = spawn_blocking(move || smtp.send(&recipient, &subject, &html)).await;

        match send_result {
            Ok(Ok(())) => {
                self.mark_sent_for_week(week).await;
                log!(ReportingLog::WeeklyReportSent);
            }
            Ok(Err(e)) => log!(ReportingLog::WeeklyReportSendFailed(e.to_string())),
            Err(e) => log!(ReportingLog::WeeklyReportSendPanicked(e.to_string())),
        }
    }

    async fn already_sent_for_week(&self, week: (i32, u32)) -> bool {
        if *self.last_sent_week.lock() == Some(week) {
            return true;
        }
        match self.db.get_report_snapshot(LAST_SENT_WEEK_SNAPSHOT_KEY).await {
            Ok(Some(value)) if parse_report_week(&value) == Some(week) => {
                *self.last_sent_week.lock() = Some(week);
                true
            }
            Ok(_) => false,
            Err(e) => {
                log!(ReportingLog::WeeklyReportSnapshotReadFailed(e.to_string()));
                false
            }
        }
    }

    async fn mark_sent_for_week(&self, week: (i32, u32)) {
        *self.last_sent_week.lock() = Some(week);
        let (year, week) = week;
        if let Err(e) = self
            .db
            .set_report_snapshot(LAST_SENT_WEEK_SNAPSHOT_KEY, &format!("{year}:{week:02}"))
            .await
        {
            log!(ReportingLog::WeeklyReportSnapshotWriteFailed(e.to_string()));
        }
    }
}

fn is_send_window(now: DateTime<Local>) -> bool {
    now.weekday() == Weekday::Mon && now.hour() == 8
}

fn report_week(now: DateTime<Local>) -> (i32, u32) {
    let week = now.iso_week();
    (week.year(), week.week())
}

fn parse_report_week(value: &str) -> Option<(i32, u32)> {
    let (year, week) = value.split_once(':')?;
    Some((year.parse().ok()?, week.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use chrono::TimeZone;

    use super::*;
    use crate::common::error::Error;
    use crate::interface::reporting::email_sender::{EmailSender, EmailSenderFactory};

    #[derive(Default)]
    struct FakeSnapshots {
        values: Mutex<HashMap<String, String>>,
    }

    #[async_trait]
    impl ReportSnapshotRepo for FakeSnapshots {
        async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
            Ok(self.values.lock().get(key).cloned())
        }

        async fn set_report_snapshot(&self, key: &str, value: &str) -> Result<(), Error> {
            self.values.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    struct CountingEmailSender {
        sent: Arc<AtomicUsize>,
    }

    impl EmailSender for CountingEmailSender {
        fn send(&self, _to: &str, _subject: &str, _html_body: &str) -> Result<(), Error> {
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct CountingEmailFactory {
        sent: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EmailSenderFactory for CountingEmailFactory {
        async fn build_smtp_sender(
            &self,
            _cfg: &crate::domain::common::config::notification::SmtpConfig,
            _secrets: Option<&dyn SecretStorePort>,
        ) -> Result<Option<Box<dyn EmailSender>>, Error> {
            Ok(Some(Box::new(CountingEmailSender {
                sent: self.sent.clone(),
            })))
        }
    }

    fn scheduler(sent: Arc<AtomicUsize>) -> ReportScheduler {
        scheduler_with_snapshots(sent, Arc::new(FakeSnapshots::default()))
    }

    fn scheduler_with_snapshots(sent: Arc<AtomicUsize>, snapshots: Arc<FakeSnapshots>) -> ReportScheduler {
        let mut cfg = AppConfig::defaults();
        cfg.notification.smtp.host = "smtp.example.test".to_string();
        cfg.notification.smtp.username = "sender@example.test".to_string();
        cfg.notification.smtp.recipient = "security@example.test".to_string();

        ReportScheduler::new(
            snapshots,
            Arc::new(ArcSwap::from_pointee(cfg)),
            None,
            Arc::new(CountingEmailFactory { sent }),
        )
    }

    #[tokio::test]
    async fn weekly_report_sends_once_per_iso_week() {
        let sent = Arc::new(AtomicUsize::new(0));
        let scheduler = scheduler(sent.clone());
        let monday_window = Local.with_ymd_and_hms(2026, 5, 4, 8, 15, 0).single().unwrap();
        let same_window = Local.with_ymd_and_hms(2026, 5, 4, 8, 45, 0).single().unwrap();
        let next_week = Local.with_ymd_and_hms(2026, 5, 11, 8, 15, 0).single().unwrap();

        scheduler.send_if_due_at(monday_window).await;
        scheduler.send_if_due_at(same_window).await;
        scheduler.send_if_due_at(next_week).await;

        assert_eq!(sent.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn weekly_report_send_marker_survives_scheduler_restart() {
        let sent = Arc::new(AtomicUsize::new(0));
        let snapshots = Arc::new(FakeSnapshots::default());
        let monday_window = Local.with_ymd_and_hms(2026, 5, 4, 8, 15, 0).single().unwrap();
        let same_window_after_restart = Local.with_ymd_and_hms(2026, 5, 4, 8, 45, 0).single().unwrap();

        scheduler_with_snapshots(sent.clone(), snapshots.clone())
            .send_if_due_at(monday_window)
            .await;
        scheduler_with_snapshots(sent.clone(), snapshots)
            .send_if_due_at(same_window_after_restart)
            .await;

        assert_eq!(sent.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn weekly_report_skips_outside_send_window() {
        let sent = Arc::new(AtomicUsize::new(0));
        let scheduler = scheduler(sent.clone());
        let monday_after_window = Local.with_ymd_and_hms(2026, 5, 4, 9, 0, 0).single().unwrap();

        scheduler.send_if_due_at(monday_after_window).await;

        assert_eq!(sent.load(Ordering::Relaxed), 0);
    }
}
