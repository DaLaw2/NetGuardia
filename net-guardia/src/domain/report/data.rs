use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone)]
pub struct ThreatBreakdownEntry {
    pub threat_type: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct TopIpEntry {
    pub ip: String,
    pub count: u64,
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
