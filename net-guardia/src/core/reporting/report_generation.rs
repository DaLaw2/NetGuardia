use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;

use super::report_engine;
use crate::common::error::Error;
use crate::domain::common::config::AppConfig;
use crate::interface::reporting::html_report_writer::HtmlReportWriter;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

pub struct ReportGenerationService {
    db: Arc<dyn ReportSnapshotRepo>,
    config: Arc<ArcSwap<AppConfig>>,
    writer: Arc<dyn HtmlReportWriter>,
}

impl ReportGenerationService {
    pub fn new(
        db: Arc<dyn ReportSnapshotRepo>,
        config: Arc<ArcSwap<AppConfig>>,
        writer: Arc<dyn HtmlReportWriter>,
    ) -> Self {
        Self { db, config, writer }
    }

    pub async fn generate_html_report(&self) -> Result<PathBuf, Error> {
        let report_dir = self.config.load().system.report_dir.clone();
        report_engine::generate_html_report(self.db.as_ref(), self.writer.as_ref(), &report_dir).await
    }

    pub async fn report_data(&self) -> Result<serde_json::Value, Error> {
        report_engine::generate_report_json(self.db.as_ref()).await
    }
}
