use crate::model::error::Error;

/// Reporting BC (generic) — weekly aggregation queries used by the report
/// scheduler and dashboard APIs.
pub trait StatsRepo: Send + Sync {
    fn count_weekly_executions(&self, days: i64) -> Result<u64, Error>;
    fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error>;
    fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error>;
    fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<(String, u64)>, Error>;
    fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<(String, u64)>, Error>;
    fn count_acl_rules(&self) -> Result<u64, Error>;
}
