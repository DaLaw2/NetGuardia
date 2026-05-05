use async_trait::async_trait;

use crate::domain::common::error::Error;
use crate::domain::report::data::{ThreatBreakdownEntry, TopIpEntry};

/// Reporting BC (generic) — weekly aggregation queries used by the report
/// scheduler and dashboard APIs.
#[async_trait]
pub trait StatsRepo: Send + Sync {
    async fn count_weekly_executions(&self, days: i64) -> Result<u64, Error>;
    async fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error>;
    async fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error>;
    async fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<ThreatBreakdownEntry>, Error>;
    async fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<TopIpEntry>, Error>;
    async fn count_acl_rules(&self) -> Result<u64, Error>;
}
