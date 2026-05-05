use chrono::{Duration as ChronoDuration, Local};

use crate::domain::common::error::Error;
use crate::domain::report::data::{
    BlockedIpItem, ExecutiveSummary, GeoItem, ReportData, SoarActivity, SystemHealthSummary, ThreatBreakdownItem,
};
use crate::interface::report_snapshot::ReportSnapshotRepo;

pub async fn build_report_data(db: &dyn ReportSnapshotRepo) -> Result<ReportData, Error> {
    let now = Local::now();
    let period = format!(
        "{} — {}",
        (now - ChronoDuration::days(7)).format("%Y-%m-%d"),
        now.format("%Y-%m-%d")
    );

    let threats_count: u64 = db
        .get_report_snapshot("weekly_threats_count")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let top_ips: Vec<BlockedIpItem> = db
        .get_report_snapshot("weekly_top_ips")
        .await?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_else(|| {
            vec![BlockedIpItem {
                ip: "—".into(),
                count: 0,
                country: "N/A".into(),
            }]
        });

    let breakdown: Vec<ThreatBreakdownItem> = db
        .get_report_snapshot("weekly_threat_breakdown")
        .await?
        .and_then(|v| {
            let obj: serde_json::Value = serde_json::from_str(&v).ok()?;
            let items = obj
                .as_object()?
                .iter()
                .map(|(k, v)| ThreatBreakdownItem {
                    threat_type: k.clone(),
                    count: v.as_u64().unwrap_or(0),
                    trend: "—".into(),
                })
                .collect();
            Some(items)
        })
        .unwrap_or_default();

    let health: SystemHealthSummary = db
        .get_report_snapshot("weekly_system_health")
        .await?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or(SystemHealthSummary {
            avg_cpu_percent: 0.0,
            avg_memory_percent: 0.0,
            disk_usage_percent: 0.0,
            ebpf_status: "running".into(),
        });

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

    let uptime_percent: f64 = db
        .get_report_snapshot("system_uptime_percent")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    let active_rules: u64 = db
        .get_report_snapshot("active_rules_count")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let geo_distribution: Vec<GeoItem> = db
        .get_report_snapshot("weekly_geo_distribution")
        .await?
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default();

    let auto_blocks: u64 = db
        .get_report_snapshot("weekly_soar_blocks")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let playbooks_triggered: u64 = db
        .get_report_snapshot("weekly_soar_triggers")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let auto_unblocks: u64 = db
        .get_report_snapshot("weekly_soar_unblocks")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let blocked_count: u64 = db
        .get_report_snapshot("weekly_blocked_count")
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(auto_blocks);

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
