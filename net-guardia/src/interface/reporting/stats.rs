use async_trait::async_trait;

use crate::common::error::Error;
use crate::domain::report::data::{ThreatBreakdownEntry, TopIpEntry};

#[async_trait]
pub trait StatsRepo: Send + Sync {
    async fn count_weekly_threat_events(&self, days: i64) -> Result<u64, Error>;
    async fn count_weekly_playbook_executions(&self, days: i64) -> Result<u64, Error>;
    async fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error>;
    async fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error>;
    async fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<ThreatBreakdownEntry>, Error>;
    async fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<TopIpEntry>, Error>;
    async fn count_acl_rules(&self) -> Result<u64, Error>;
}
