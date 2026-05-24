use std::fmt::Display;
use std::str::FromStr;

use chrono::{Duration as ChronoDuration, Local};
use serde::de::DeserializeOwned;

use crate::common::error::Error;
use crate::domain::report::data::{
    BlockedIpItem, ExecutiveSummary, GeoItem, ReportData, SoarActivity, SystemHealthSummary, ThreatBreakdownItem,
};
use crate::domain::report::error::ReportError;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;

async fn parsed_snapshot<T>(db: &dyn ReportSnapshotRepo, key: &str, default: T) -> Result<T, Error>
where
    T: FromStr,
    T::Err: Display,
{
    match db.get_report_snapshot(key).await? {
        Some(value) => {
            let parsed = value
                .parse()
                .map_err(|err| ReportError::SnapshotParseFailed(key, value, err))?;
            Ok(parsed)
        }
        None => Ok(default),
    }
}

async fn json_snapshot<T>(db: &dyn ReportSnapshotRepo, key: &str, default: T) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    match db.get_report_snapshot(key).await? {
        Some(value) => {
            let parsed =
                serde_json::from_str(&value).map_err(|err| ReportError::SnapshotParseFailed(key, value, err))?;
            Ok(parsed)
        }
        None => Ok(default),
    }
}

async fn threat_breakdown_snapshot(db: &dyn ReportSnapshotRepo) -> Result<Vec<ThreatBreakdownItem>, Error> {
    let key = "weekly_threat_breakdown";
    let Some(value) = db.get_report_snapshot(key).await? else {
        return Ok(Vec::new());
    };
    let obj: serde_json::Value =
        serde_json::from_str(&value).map_err(|err| ReportError::SnapshotParseFailed(key, value, err))?;
    let Some(entries) = obj.as_object() else {
        return Err(ReportError::SnapshotShapeInvalid(key, "object of threat_type to count").into());
    };

    let mut items = Vec::with_capacity(entries.len());
    for (threat_type, count) in entries {
        let Some(count) = count.as_u64() else {
            return Err(ReportError::SnapshotShapeInvalid(key, "object of threat_type to unsigned count").into());
        };
        items.push(ThreatBreakdownItem {
            threat_type: threat_type.clone(),
            count,
            trend: "—".into(),
        });
    }
    Ok(items)
}

pub async fn build_report_data(db: &dyn ReportSnapshotRepo) -> Result<ReportData, Error> {
    let now = Local::now();
    let period = format!(
        "{} — {}",
        (now - ChronoDuration::days(7)).format("%Y-%m-%d"),
        now.format("%Y-%m-%d")
    );

    let threats_count = parsed_snapshot(db, "weekly_threats_count", 0_u64).await?;

    let top_ips = json_snapshot(db, "weekly_top_ips", Vec::<BlockedIpItem>::new()).await?;

    let breakdown = threat_breakdown_snapshot(db).await?;

    let health = json_snapshot(
        db,
        "weekly_system_health",
        SystemHealthSummary {
            avg_cpu_percent: 0.0,
            avg_memory_percent: 0.0,
            disk_usage_percent: 0.0,
            ebpf_status: "running".into(),
        },
    )
    .await?;

    let mut recommendations = Vec::new();
    if threats_count > 10 {
        recommendations.push("Consider enabling geo-blocking for high-risk regions".into());
    }
    if breakdown.iter().any(|b| b.threat_type == "port_scan" && b.count > 50) {
        recommendations.push("Review exposed ports and consider tightening protocol filter rules".into());
    }
    if recommendations.is_empty() {
        recommendations.push("No action needed — your network security posture is healthy".into());
    }

    let uptime_percent = parsed_snapshot(db, "system_uptime_percent", 0.0_f64).await?;

    let active_rules = parsed_snapshot(db, "active_rules_count", 0_u64).await?;

    let geo_distribution = json_snapshot(db, "weekly_geo_distribution", Vec::<GeoItem>::new()).await?;

    let auto_blocks = parsed_snapshot(db, "weekly_soar_blocks", 0_u64).await?;
    let playbooks_triggered = parsed_snapshot(db, "weekly_soar_triggers", 0_u64).await?;
    let auto_unblocks = parsed_snapshot(db, "weekly_soar_unblocks", 0_u64).await?;

    let blocked_count = parsed_snapshot(db, "weekly_blocked_count", auto_blocks).await?;

    Ok(ReportData {
        period,
        generated_at: now.format("%Y-%m-%d %H:%M:%S").to_string(),
        executive_summary: ExecutiveSummary {
            total_threats: threats_count,
            total_blocked: blocked_count,
            uptime_percent,
            active_rules,
        },
        threat_breakdown: breakdown,
        top_blocked_ips: top_ips,
        geo_distribution,
        soar_activity: SoarActivity {
            auto_blocks_executed: auto_blocks,
            playbooks_triggered,
            auto_unblocks,
        },
        system_health: health,
        recommendations,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeSnapshots {
        values: HashMap<String, String>,
    }

    #[async_trait::async_trait]
    impl ReportSnapshotRepo for FakeSnapshots {
        async fn get_report_snapshot(&self, key: &str) -> Result<Option<String>, Error> {
            Ok(self.values.get(key).cloned())
        }

        async fn set_report_snapshot(&self, _key: &str, _value: &str) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn missing_snapshots_use_defaults() {
        let repo = FakeSnapshots { values: HashMap::new() };

        let data = build_report_data(&repo)
            .await
            .expect("missing snapshots should default");

        assert_eq!(data.executive_summary.total_threats, 0);
        assert!(data.top_blocked_ips.is_empty());
        assert!(data.threat_breakdown.is_empty());
    }

    #[tokio::test]
    async fn invalid_numeric_snapshot_is_an_error() {
        let mut values = HashMap::new();
        values.insert("weekly_threats_count".to_string(), "not-a-number".to_string());
        let repo = FakeSnapshots { values };

        let err = build_report_data(&repo)
            .await
            .expect_err("invalid numeric snapshot should fail");

        assert!(err.to_string().contains("weekly_threats_count"));
    }

    #[tokio::test]
    async fn invalid_json_snapshot_is_an_error() {
        let mut values = HashMap::new();
        values.insert("weekly_top_ips".to_string(), "{bad json".to_string());
        let repo = FakeSnapshots { values };

        let err = build_report_data(&repo)
            .await
            .expect_err("invalid JSON snapshot should fail");

        assert!(err.to_string().contains("weekly_top_ips"));
    }

    #[tokio::test]
    async fn invalid_threat_breakdown_shape_is_an_error() {
        let mut values = HashMap::new();
        values.insert(
            "weekly_threat_breakdown".to_string(),
            r#"{"port_scan":"many"}"#.to_string(),
        );
        let repo = FakeSnapshots { values };

        let err = build_report_data(&repo)
            .await
            .expect_err("invalid breakdown shape should fail");

        assert!(err.to_string().contains("weekly_threat_breakdown"));
    }
}
