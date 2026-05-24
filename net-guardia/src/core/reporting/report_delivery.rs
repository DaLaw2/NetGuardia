use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::Local;
use tokio::task::spawn_blocking;

use super::email_report;
use crate::domain::common::config::AppConfig;
use crate::domain::report::error::ReportError;
use crate::interface::reporting::email_sender::EmailSenderFactory;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;
use crate::interface::system::secret_store::SecretStorePort;

pub struct ReportDeliveryService {
    db: Arc<dyn ReportSnapshotRepo>,
    config: Arc<ArcSwap<AppConfig>>,
    secrets: Option<Arc<dyn SecretStorePort>>,
    email_sender_factory: Arc<dyn EmailSenderFactory>,
}

impl ReportDeliveryService {
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

    pub async fn send_weekly_report_now(&self) -> Result<(), ReportError> {
        let smtp_cfg = self.config.load().notification.smtp.clone();
        let smtp = self
            .email_sender_factory
            .build_smtp_sender(&smtp_cfg, self.secrets.as_deref())
            .await
            .map_err(ReportError::SettingsReadFailed)?
            .ok_or(ReportError::SmtpNotConfigured)?;

        let recipient = smtp_cfg.recipient;
        if recipient.is_empty() {
            return Err(ReportError::RecipientMissing);
        }

        let html = email_report::generate_weekly_report(&*self.db)
            .await
            .map_err(ReportError::GenerationFailed)?;
        let subject = format!("NetGuardia Weekly Report — {}", Local::now().format("%Y-%m-%d"));

        spawn_blocking(move || smtp.send(&recipient, &subject, &html))
            .await
            .map_err(ReportError::SendTaskFailed)?
            .map_err(ReportError::SendFailed)
    }
}
