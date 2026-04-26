use rusqlite::params;

use super::Database;
use crate::domain::common::error::Error;
use crate::domain::report::data::{ThreatBreakdownEntry, TopIpEntry};
use crate::interface::stats::StatsRepo;

impl Database {
    /// Count SOAR executions in the last N days.
    pub fn count_weekly_executions(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_executions WHERE executed_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Count SOAR blocks created in the last N days.
    pub fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE created_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Count SOAR unblocks in the last N days.
    pub fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM soar_block_rules WHERE unblocked_at IS NOT NULL AND unblocked_at >= datetime('now', ?1)",
            params![format!("-{} days", days)],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Get threat breakdown by trigger_event in the last N days.
    pub fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<ThreatBreakdownEntry>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT trigger_event, COUNT(*) FROM soar_executions WHERE executed_at >= datetime('now', ?1) GROUP BY trigger_event ORDER BY COUNT(*) DESC"
        )?;
        let rows = stmt.query_map(params![format!("-{} days", days)], |row| {
            Ok(ThreatBreakdownEntry {
                threat_type: row.get(0)?,
                count: row.get::<_, i64>(1)? as u64,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Get top blocked IPs in the last N days.
    pub fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<TopIpEntry>, Error> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT source_ip, COUNT(*) as cnt FROM soar_block_rules WHERE created_at >= datetime('now', ?1) GROUP BY source_ip ORDER BY cnt DESC LIMIT ?2"
        )?;
        let rows = stmt.query_map(params![format!("-{} days", days), limit], |row| {
            Ok(TopIpEntry {
                ip: row.get(0)?,
                count: row.get::<_, i64>(1)? as u64,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Count current ACL rules.
    pub fn count_acl_rules(&self) -> Result<u64, Error> {
        let conn = self.conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM acl_rules", [], |row| row.get(0))?;
        Ok(count as u64)
    }
}

impl StatsRepo for Database {
    fn count_weekly_executions(&self, days: i64) -> Result<u64, Error> {
        self.count_weekly_executions(days)
    }

    fn count_weekly_blocks(&self, days: i64) -> Result<u64, Error> {
        self.count_weekly_blocks(days)
    }

    fn count_weekly_unblocks(&self, days: i64) -> Result<u64, Error> {
        self.count_weekly_unblocks(days)
    }

    fn weekly_threat_breakdown(&self, days: i64) -> Result<Vec<ThreatBreakdownEntry>, Error> {
        self.weekly_threat_breakdown(days)
    }

    fn weekly_top_ips(&self, days: i64, limit: i64) -> Result<Vec<TopIpEntry>, Error> {
        self.weekly_top_ips(days, limit)
    }

    fn count_acl_rules(&self) -> Result<u64, Error> {
        self.count_acl_rules()
    }
}
