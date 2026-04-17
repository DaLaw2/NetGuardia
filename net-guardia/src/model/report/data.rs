use chrono::{Duration as ChronoDuration, Local};
use serde::{Deserialize, Serialize};

use crate::interface::port::setting::SettingRepo;
use crate::model::error::Error;

/// Shared report data structure used by both HTML email and PDF report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub period: String,
    pub generated_at: String,
    pub executive_summary: ExecutiveSummary,
    pub threat_breakdown: Vec<ThreatBreakdownItem>,
    pub top_blocked_ips: Vec<BlockedIpItem>,
    pub geo_distribution: Vec<GeoItem>,
    pub soar_activity: SoarActivity,
    pub system_health: SystemHealthSummary,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutiveSummary {
    pub total_threats: u64,
    pub total_blocked: u64,
    pub uptime_percent: f64,
    pub active_rules: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatBreakdownItem {
    pub threat_type: String,
    pub count: u64,
    pub trend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpItem {
    pub ip: String,
    pub count: u64,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoItem {
    pub country: String,
    pub threat_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoarActivity {
    pub auto_blocks_executed: u64,
    pub playbooks_triggered: u64,
    pub auto_unblocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealthSummary {
    pub avg_cpu_percent: f64,
    pub avg_memory_percent: f64,
    pub disk_usage_percent: f64,
    pub ebpf_status: String,
}

impl ReportData {
    /// Build report data from database settings (aggregated by the ML pipeline).
    pub fn from_database(db: &dyn SettingRepo) -> Result<Self, Error> {
        let now = Local::now();
        let period = format!(
            "{} — {}",
            (now - ChronoDuration::days(7)).format("%Y-%m-%d"),
            now.format("%Y-%m-%d")
        );

        let threats_count: u64 = db
            .get_setting("weekly_threats_count")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let top_ips: Vec<BlockedIpItem> = db
            .get_setting("weekly_top_ips")?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_else(|| {
                vec![BlockedIpItem {
                    ip: "—".into(),
                    count: 0,
                    country: "N/A".into(),
                }]
            });

        let breakdown: Vec<ThreatBreakdownItem> = db
            .get_setting("weekly_threat_breakdown")?
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
            .get_setting("weekly_system_health")?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or(SystemHealthSummary {
                avg_cpu_percent: 0.0,
                avg_memory_percent: 0.0,
                disk_usage_percent: 0.0,
                ebpf_status: "running".into(),
            });

        // Generate recommendations based on data
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
            .get_setting("system_uptime_percent")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0);

        let active_rules: u64 = db
            .get_setting("active_rules_count")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let geo_distribution: Vec<GeoItem> = db
            .get_setting("weekly_geo_distribution")?
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_default();

        let auto_blocks: u64 = db
            .get_setting("weekly_soar_blocks")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let playbooks_triggered: u64 = db
            .get_setting("weekly_soar_triggers")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let auto_unblocks: u64 = db
            .get_setting("weekly_soar_unblocks")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let blocked_count: u64 = db
            .get_setting("weekly_blocked_count")?
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
}
