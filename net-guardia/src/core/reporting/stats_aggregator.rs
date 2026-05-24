use std::sync::Arc;

use macros::log;
use serde::Serialize;

use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::common::log::reporting::ReportingLog;
use crate::domain::report::data::{BlockedIpItem, SystemHealthSummary};
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;
use crate::interface::reporting::stats::StatsRepo;
use crate::interface::system::health_query::HealthQuery;

fn serialize_snapshot_value<T: Serialize>(value: &T) -> Result<String, Error> {
    let serialized = serde_json::to_string(value).map_err(CodecError::SerializeFailed)?;
    Ok(serialized)
}

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

    pub async fn aggregate(&self) -> Result<(), Error> {
        let days = 7;

        let threat_events_count = self.stats.count_weekly_threat_events(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_threats_count", &threat_events_count.to_string())
            .await?;

        let playbook_executions_count = self.stats.count_weekly_playbook_executions(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_soar_triggers", &playbook_executions_count.to_string())
            .await?;

        let blocks_count = self.stats.count_weekly_blocks(days).await?;
        self.snapshots
            .set_report_snapshot("weekly_soar_blocks", &blocks_count.to_string())
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
            .map(|entry| (entry.threat_type, serde_json::Value::Number(entry.count.into())))
            .collect();
        self.snapshots
            .set_report_snapshot("weekly_threat_breakdown", &serialize_snapshot_value(&breakdown_json)?)
            .await?;

        let top_ips = self.stats.weekly_top_ips(days, 10).await?;
        let top_ips: Vec<BlockedIpItem> = top_ips
            .into_iter()
            .map(|entry| BlockedIpItem {
                ip: entry.ip,
                count: entry.count,
                country: "N/A".to_string(),
            })
            .collect();
        self.snapshots
            .set_report_snapshot("weekly_top_ips", &serialize_snapshot_value(&top_ips)?)
            .await?;

        let active_rules = self.stats.count_acl_rules().await?;
        self.snapshots
            .set_report_snapshot("active_rules_count", &active_rules.to_string())
            .await?;

        {
            let metrics = self.health.get_current_metrics();
            let cpu_usage = metrics.cpu_details.cpu_usage as f64;
            let mem_percent = metrics.memory_usage.usage_percent as f64;

            let health = SystemHealthSummary {
                avg_cpu_percent: cpu_usage,
                avg_memory_percent: mem_percent,
                disk_usage_percent: 0.0,
                ebpf_status: metrics.ebpf.public_status().to_string(),
            };
            self.snapshots
                .set_report_snapshot("weekly_system_health", &serialize_snapshot_value(&health)?)
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

        log!(ReportingLog::StatsAggregated(
            threat_events_count,
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
    use crate::core::common::config_loader::load_app_config;
    use crate::domain::common::config::constants::{FUSION_AUDIT_ACTION, FUSION_AUDIT_ACTOR};
    use crate::domain::common::system::health::EbpfHealth;
    use crate::domain::data_plane::ip_version::IpVersion;
    use crate::infrastructure::health::SystemHealth;

    async fn test_health(db: &Arc<Database>) -> Arc<dyn HealthQuery> {
        use arc_swap::ArcSwap;
        let config = Arc::new(ArcSwap::from_pointee(load_app_config(db.as_ref()).await.unwrap()));
        let ebpf_health = Arc::new(ArcSwap::from_pointee(EbpfHealth::Healthy));
        Arc::new(SystemHealth::new(config, ebpf_health).unwrap())
    }

    #[tokio::test]
    async fn aggregator_writes_weekly_stats() {
        let db = Arc::new(Database::new(":memory:").await.expect("test db"));

        db.seed_default_playbooks().await.ok();
        db.insert_soar_execution(1, Some("1.2.3.4"), "threat_detected", "[]")
            .await
            .ok();
        db.insert_soar_execution(1, Some("5.6.7.8"), "brute_force", "[]")
            .await
            .ok();
        let brute_force_detail = serde_json::json!({
            "src_ip": "1.2.3.4",
            "attack_type": "brute_force",
        })
        .to_string();
        let port_scan_detail = serde_json::json!({
            "src_ip": "5.6.7.8",
            "attack_type": "port_scan",
        })
        .to_string();
        db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &brute_force_detail)
            .await
            .ok();
        db.insert_audit_log(FUSION_AUDIT_ACTOR, FUSION_AUDIT_ACTION, &port_scan_detail)
            .await
            .ok();
        db.commit_soar_block_to_db("1.2.3.4", IpVersion::V4, 1, "2099-01-01 00:00:00")
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

        let triggers = db.get_report_snapshot("weekly_soar_triggers").await.unwrap().unwrap();
        assert_eq!(triggers, "2");

        let blocks = db.get_report_snapshot("weekly_soar_blocks").await.unwrap().unwrap();
        assert_eq!(blocks, "1");

        let top_ips = db.get_report_snapshot("weekly_top_ips").await;
        assert!(matches!(top_ips, Ok(Some(value)) if value.contains("\"country\":\"N/A\"")));

        let breakdown = db
            .get_report_snapshot("weekly_threat_breakdown")
            .await
            .unwrap()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&breakdown).unwrap();
        assert!(parsed["threat_detected"].is_null());
        assert_eq!(parsed["brute_force"], 1);
        assert_eq!(parsed["port_scan"], 1);

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
