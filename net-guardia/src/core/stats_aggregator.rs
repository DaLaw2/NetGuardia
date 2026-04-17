use std::sync::Arc;

use macros::log;
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::interface::port::setting::SettingRepo;
use crate::interface::port::stats::StatsRepo;
use crate::model::error::Error;
use crate::model::log::system::SystemLog;

/// Background service that periodically aggregates statistics from SOAR/ML tables
/// and writes them to the settings table for the Report engine to consume.
pub struct StatsAggregator {
    stats: Arc<dyn StatsRepo>,
    repo: Arc<dyn SettingRepo>,
}

impl StatsAggregator {
    pub fn new(stats: Arc<dyn StatsRepo>, repo: Arc<dyn SettingRepo>) -> Self {
        Self { stats, repo }
    }

    /// Spawn a background task that runs aggregation every hour.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            log!(SystemLog::StatsAggregatorStarted);
            // Run immediately on startup
            if let Err(e) = self.aggregate() {
                log!(SystemLog::InitialStatsAggregationFailed(e.to_string()));
            }
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = self.aggregate() {
                    log!(SystemLog::StatsAggregationFailed(e.to_string()));
                }
            }
        })
    }

    /// Aggregate all weekly statistics and write to settings.
    pub fn aggregate(&self) -> Result<(), Error> {
        let days = 7;

        // SOAR execution counts
        let threats_count = self.stats.count_weekly_executions(days)?;
        self.repo
            .set_setting("weekly_threats_count", &threats_count.to_string())?;

        let blocks_count = self.stats.count_weekly_blocks(days)?;
        self.repo.set_setting("weekly_soar_blocks", &blocks_count.to_string())?;
        self.repo
            .set_setting("weekly_soar_triggers", &threats_count.to_string())?;

        let unblocks_count = self.stats.count_weekly_unblocks(days)?;
        self.repo
            .set_setting("weekly_soar_unblocks", &unblocks_count.to_string())?;

        self.repo
            .set_setting("weekly_blocked_count", &blocks_count.to_string())?;

        // Threat breakdown by type
        let breakdown = self.stats.weekly_threat_breakdown(days)?;
        let breakdown_json: serde_json::Map<String, serde_json::Value> = breakdown
            .into_iter()
            .map(|(k, v)| (k, Value::Number(v.into())))
            .collect();
        self.repo.set_setting(
            "weekly_threat_breakdown",
            &serde_json::to_string(&breakdown_json).unwrap_or_else(|_| "{}".to_string()),
        )?;

        // Top blocked IPs
        let top_ips = self.stats.weekly_top_ips(days, 10)?;
        let top_ips_json: Vec<serde_json::Value> = top_ips
            .into_iter()
            .map(|(ip, count)| {
                serde_json::json!({
                    "ip": ip,
                    "count": count,
                    "country": "N/A",
                })
            })
            .collect();
        self.repo.set_setting(
            "weekly_top_ips",
            &serde_json::to_string(&top_ips_json).unwrap_or_else(|_| "[]".to_string()),
        )?;

        // Active rules count
        let active_rules = self.stats.count_acl_rules()?;
        self.repo.set_setting("active_rules_count", &active_rules.to_string())?;

        // System health snapshot using sysinfo
        {
            use sysinfo::System;
            let mut sys = System::new();
            sys.refresh_cpu_all();
            sys.refresh_memory();
            let cpu_usage = sys.global_cpu_usage() as f64;
            let mem_total = sys.total_memory();
            let mem_used = sys.used_memory();
            let mem_percent = if mem_total > 0 {
                (mem_used as f64 / mem_total as f64) * 100.0
            } else {
                0.0
            };

            let health_json = serde_json::json!({
                "avg_cpu_percent": cpu_usage,
                "avg_memory_percent": mem_percent,
                "disk_usage_percent": 0.0,
                "ebpf_status": "running",
            });
            self.repo.set_setting(
                "weekly_system_health",
                &serde_json::to_string(&health_json).unwrap_or_else(|_| "{}".to_string()),
            )?;

            // System uptime
            let uptime_secs = System::uptime();
            let week_secs = (days as u64) * 86400;
            let uptime_percent = if uptime_secs >= week_secs {
                100.0
            } else {
                (uptime_secs as f64 / week_secs as f64) * 100.0
            };
            self.repo
                .set_setting("system_uptime_percent", &format!("{:.1}", uptime_percent))?;
        }

        // Geo distribution (initialize if not present)
        if self.repo.get_setting("weekly_geo_distribution")?.is_none() {
            self.repo.set_setting("weekly_geo_distribution", "[]")?;
        }

        log!(SystemLog::StatsAggregated(
            threats_count,
            blocks_count,
            unblocks_count,
            active_rules,
        ));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    #[test]
    fn aggregator_writes_weekly_stats() {
        let db = Arc::new(Database::new(":memory:").expect("test db"));

        // Seed some SOAR executions
        db.seed_default_playbooks().ok();
        db.insert_soar_execution(1, Some("1.2.3.4"), "threat_detected", "[]")
            .ok();
        db.insert_soar_execution(1, Some("5.6.7.8"), "brute_force", "[]").ok();
        db.insert_soar_block_rule("1.2.3.4", 1, "2099-01-01 00:00:00").ok();

        let aggregator = StatsAggregator::new(db.clone() as Arc<dyn StatsRepo>, db.clone() as Arc<dyn SettingRepo>);
        aggregator.aggregate().expect("aggregation should succeed");

        // Verify settings were written
        let threats = db.get_setting("weekly_threats_count").unwrap().unwrap();
        assert_eq!(threats, "2");

        let blocks = db.get_setting("weekly_soar_blocks").unwrap().unwrap();
        assert_eq!(blocks, "1");

        let breakdown = db.get_setting("weekly_threat_breakdown").unwrap().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&breakdown).unwrap();
        assert_eq!(parsed["threat_detected"], 1);
        assert_eq!(parsed["brute_force"], 1);

        let active_rules = db.get_setting("active_rules_count").unwrap().unwrap();
        assert_eq!(active_rules, "0");

        let uptime = db.get_setting("system_uptime_percent").unwrap().unwrap();
        assert!(!uptime.is_empty());

        let health = db.get_setting("weekly_system_health").unwrap().unwrap();
        let health_val: serde_json::Value = serde_json::from_str(&health).unwrap();
        assert!(health_val["ebpf_status"].as_str() == Some("running"));
    }

    #[test]
    fn aggregator_handles_empty_db() {
        let db = Arc::new(Database::new(":memory:").expect("test db"));
        let aggregator = StatsAggregator::new(db.clone() as Arc<dyn StatsRepo>, db.clone() as Arc<dyn SettingRepo>);
        aggregator
            .aggregate()
            .expect("aggregation should succeed with empty data");

        let threats = db.get_setting("weekly_threats_count").unwrap().unwrap();
        assert_eq!(threats, "0");
    }
}
