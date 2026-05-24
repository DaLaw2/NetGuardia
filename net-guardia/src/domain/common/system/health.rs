use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealthMetrics {
    pub timestamp: u64,
    pub boot_time: u64,
    pub uptime_seconds: u64,
    pub system_info: SystemInfo,
    pub cpu_details: CpuDetails,
    pub memory_usage: MemoryUsage,
    pub network_stats: ConfiguredNetworkStats,
    pub load_average: Option<LoadAverage>,
    pub temperature: Option<f32>,
    pub ebpf: EbpfHealth,
}

#[derive(Debug, Clone)]
pub enum EbpfHealth {
    Healthy,
    Unavailable,
}

impl EbpfHealth {
    pub fn public_status(&self) -> &'static str {
        match self {
            Self::Healthy => "running",
            Self::Unavailable => "unavailable",
        }
    }

    fn public_state(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Unavailable => "unavailable",
        }
    }

    fn public_message(&self) -> &'static str {
        match self {
            Self::Healthy => "Security engine is active.",
            Self::Unavailable => "Security engine is unavailable.",
        }
    }
}

impl Serialize for EbpfHealth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EbpfHealth", 3)?;
        state.serialize_field("state", self.public_state())?;
        state.serialize_field("status", self.public_status())?;
        state.serialize_field("message", self.public_message())?;
        state.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub kernel_version: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub architecture: String,
    pub total_processes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuDetails {
    pub cpu_brand: String,
    pub core_count: usize,
    pub cpu_usage: f32,
    pub cpu_frequency: u64,
    pub cores: Vec<CpuCoreInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuCoreInfo {
    pub core_id: usize,
    pub usage_percent: f32,
    pub frequency: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryUsage {
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub usage_percent: f32,
    pub swap_total: u64,
    pub swap_used: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfiguredNetworkStats {
    pub ingress: Option<NetworkStats>,
    pub egress: Option<NetworkStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStats {
    pub interface: String,
    pub bytes_received: u64,
    pub bytes_transmitted: u64,
    pub packets_received: u64,
    pub packets_transmitted: u64,
    pub errors_received: u64,
    pub errors_transmitted: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadAverage {
    pub one_minute: f64,
    pub five_minute: f64,
    pub fifteen_minute: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealthStatus {
    pub overall_healthy: bool,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
}
