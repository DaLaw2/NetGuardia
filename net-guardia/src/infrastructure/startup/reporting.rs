use std::sync::Arc;

use crate::adapter::html_report_writer::FsHtmlReportWriter;
use crate::adapter::notification::smtp::SmtpClientFactory;
use crate::core::reporting::email_scheduler::ReportScheduler;
use crate::core::reporting::report_delivery::ReportDeliveryService;
use crate::core::reporting::report_generation::ReportGenerationService;
use crate::infrastructure::startup::{FoundationRuntime, ReportingRuntime};
use crate::interface::reporting::email_sender::EmailSenderFactory;
use crate::interface::reporting::html_report_writer::HtmlReportWriter;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

pub async fn build_reporting(foundation: &FoundationRuntime) -> ReportingRuntime {
    let email_sender_factory: Arc<dyn EmailSenderFactory> = Arc::new(SmtpClientFactory);
    let report_scheduler = ReportScheduler::new(
        foundation.database.clone() as Arc<dyn ReportSnapshotRepo>,
        foundation.app_config.clone(),
        Some(foundation.secret_store_port.clone()),
        email_sender_factory.clone(),
    );
    let report_delivery_service = Arc::new(ReportDeliveryService::new(
        foundation.database.clone() as Arc<dyn ReportSnapshotRepo>,
        foundation.app_config.clone(),
        Some(foundation.secret_store_port.clone()),
        email_sender_factory,
    ));
    let report_generation_service = Arc::new(ReportGenerationService::new(
        foundation.database.clone() as Arc<dyn ReportSnapshotRepo>,
        foundation.app_config.clone(),
        Arc::new(FsHtmlReportWriter) as Arc<dyn HtmlReportWriter>,
    ));

    ReportingRuntime {
        report_generation_service,
        report_delivery_service,
        report_scheduler: Some(report_scheduler),
    }
}
