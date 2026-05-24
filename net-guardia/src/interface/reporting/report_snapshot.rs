use async_trait::async_trait;

use crate::common::error::Error;

#[async_trait]
pub trait ReportSnapshotRepo: Send + Sync {
    async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error>;
    async fn set_report_snapshot(&self, key: &str, value: &str) -> Result<(), Error>;
}
