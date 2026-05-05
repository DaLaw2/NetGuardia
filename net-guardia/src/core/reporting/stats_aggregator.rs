use std::sync::Arc;

use macros::log;
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};

use crate::domain::common::error::Error;
use crate::domain::common::log::system::SystemLog;
use crate::interface::health_query::HealthQuery;
use crate::interface::report_snapshot::ReportSnapshotRepo;
use crate::interface::stats::StatsRepo;

pub struct StatsAggregator {
    stats: Arc<dyn StatsRepo>,
    snapshots: Arc<dyn ReportSnapshotRepo>,
    health: Arc<dyn HealthQuery>,
}

impl StatsAggregator {
    pub fn new(
        stats: Arc<dyn StatsRepo>,
        snapshots: Arc<dyn ReportSnapshotRepo>,
        health: Arc<dyn HealthQuery>,
    ) -> Self {
        Self {
            stats,
            snapshots,
            health,
        }
    }

    /// Spawn a background task that runs aggregation every hour.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            log!(SystemLog::StatsAggregatorStarted);
            // Run immediately on startup
            if let Err(e) = self.aggregate().await {
                log!(SystemLog::InitialStatsAggregationFailed(e.to_string()));
            }
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = self.aggregate().await {
                    log!(SystemLog::StatsAggregationFailed(e.to_string()));
                }
            }
        })
    }

    /// Aggregate all weekly statistics and write to the report snapshot store.
    pub async fn aggregate(&self) -> Result<(), Error> {
        let days = 7;

        // SOAR execution counts
        let threats_count = self.stats.count_weekly_executions(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_threats_count", &threats_count.to_string())
            .await?;

        let blocks_count = self.stats.count_weekly_blocks(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_soar_blocks", &blocks_count.to_string())
            .await?;
        self.snapshots
            .set_report_snapshot("weekly_soar_triggers", &threats_count.to_string())
            .await?;

        let unblocks_count = self.stats.count_weekly_unblocks(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_soar_unblocks", &unblocks_count.to_string())
            .await?;

        self.snapshots
            .set_report_snapshot("weekly_blocked_count", &blocks_count.to_string())
            .await?;

        let breakdown = self.stats.weekly_threat_breakdown(days).await?;
        let breakdown_json: serde_json::Map<String, serde_json::Value> = breakdown
            .into_iter()
            .map(|entry| (entry.threat_type, Value::Number(entry.count.into())))
            .collect();
        self.snapshots
            .set_report_snapshot(
                "weekly_threat_breakdown",
                &serde_json::to_string(&breakdown_json).unwrap_or_else(|_| "{}".to_string()),
            )
            .await?;

        let top_ips = self.stats.weekly_top_ips(days, 10).await?;
        let top_ips_json: Vec<serde_json::Value> = top_ips
            .into_iter()
            .map(|entry| {
                serde_json::json!({
                    "ip": entry.ip,
                    "count": entry.count,
                    "country": "N/A",
                })
            })
            .collect();
        self.snapshots
            .set_report_snapshot(
                "weekly_top_ips",
                &serde_json::to_string(&top_ips_json).unwrap_or_else(|_| "[]".to_string()),
            )
            .await?;

        // Active rules count
        let active_rules = self.stats.count_acl_rules().await?;
        self.snapshots
            .set_report_snapshot("active_rules_count", &active_rules.to_string())
            .await?;

        {
            let metrics = self.health.get_current_metrics();
            let cpu_usage = metrics.cpu_details.cpu_usage as f64;
            let mem_percent = metrics.memory_usage.usage_percent as f64;

            let health_json = serde_json::json!({
                "avg_cpu_percent": cpu_usage,
                "avg_memory_percent": mem_percent,
                "disk_usage_percent": 0.0,
                "ebpf_status": format!("{:?}", metrics.ebpf),
            });
            self.snapshots
                .set_report_snapshot(
                    "weekly_system_health",
                    &serde_json::to_string(&health_json).unwrap_or_else(|_| "{}".to_string()),
                )
                .await?;

            let uptime_secs = metrics.uptime_seconds;
            let week_secs = (days as u64) * 86400;
            let uptime_percent = if uptime_secs >= week_secs {
                100.0
            } else {
                (uptime_secs as f64 / week_secs as f64) * 100.0
            };
            self.snapshots
                .set_report_snapshot("system_uptime_percent", &format!("{:.1}", uptime_percent))
                .await?;
        }

        // Geo distribution (initialize if not present)
        if self
            .snapshots
            .get_report_snapshot("weekly_geo_distribution")
            .await?
            .is_none()
        {
            self.snapshots
                .set_report_snapshot("weekly_geo_distribution", "[]")
                .await?;
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
    use crate::domain::common::config::AppConfig;
    use crate::domain::common::system::health::EbpfHealth;
    use crate::infrastructure::health::SystemHealth;

    async fn test_health(db: &Arc<Database>) -> Arc<dyn HealthQuery> {
        use arc_swap::ArcSwap;
        let config = Arc::new(ArcSwap::from_pointee(
            AppConfig::from_config_repo(db.as_ref()).await.unwrap(),
        ));
        let ebpf_health = Arc::new(ArcSwap::from_pointee(EbpfHealth::Healthy));
        Arc::new(SystemHealth::new(config, ebpf_health).unwrap())
    }

    #[tokio::test]
    async fn aggregator_writes_weekly_stats() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));

        // Seed some SOAR executions
        db.seed_default_playbooks().await.ok();
        db.insert_soar_execution(1, Some("1.2.3.4"), "threat_detected", "[]")
            .await
            .ok();
        db.insert_soar_execution(1, Some("5.6.7.8"), "brute_force", "[]")
            .await
            .ok();
        db.commit_soar_block_to_db("1.2.3.4", 4, 1, "2099-01-01 00:00:00")
            .await
            .ok();

        let health = test_health(&db).await;
        let aggregator = StatsAggregator::new(
            db.clone() as Arc<dyn StatsRepo>,
            db.clone() as Arc<dyn ReportSnapshotRepo>,
            health,
        );
        aggregator.aggregate().await.expect("aggregation should succeed");

        let threats = db.get_report_snapshot("weekly_threats_count").await.unwrap().unwrap();
        assert_eq!(threats, "2");

        let blocks = db.get_report_snapshot("weekly_soar_blocks").await.unwrap().unwrap();
        assert_eq!(blocks, "1");

        let breakdown = db
            .get_report_snapshot("weekly_threat_breakdown")
            .await
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&breakdown).unwrap();
        assert_eq!(parsed["threat_detected"], 1);
        assert_eq!(parsed["brute_force"], 1);

        let active_rules = db.get_report_snapshot("active_rules_count").await.unwrap().unwrap();
        assert_eq!(active_rules, "1");

        let uptime = db.get_report_snapshot("system_uptime_percent").await.unwrap().unwrap();
        assert!(!uptime.is_empty());

        let sys_health = db.get_report_snapshot("weekly_system_health").await.unwrap().unwrap();
        let health_val: serde_json::Value = serde_json::from_str(&sys_health).unwrap();
        assert!(health_val["avg_cpu_percent"].as_f64().is_some());
    }

    #[tokio::test]
    async fn aggregator_handles_empty_db() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));
        let health = test_health(&db).await;
        let aggregator = StatsAggregator::new(
            db.clone() as Arc<dyn StatsRepo>,
            db.clone() as Arc<dyn ReportSnapshotRepo>,
            health,
        );
        aggregator
            .aggregate()
            .await
            .expect("aggregation should succeed with empty data");

        let threats = db.get_report_snapshot("weekly_threats_count").await.unwrap().unwrap();
        assert_eq!(threats, "0");
    }
}
