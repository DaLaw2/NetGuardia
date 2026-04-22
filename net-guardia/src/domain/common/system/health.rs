use serde::Serialize;

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

/// Runtime health of the eBPF/XDP data plane.
///
/// `Healthy` means both ingress and egress XDP programs are attached and AF_XDP
/// sockets are bound. `Unavailable` means one of the eBPF setup stages failed;
/// the rest of the system continues to run but any eBPF-backed operation
/// (access control rules, geo block, rate limit, DNS filter, packet capture)
/// will return `EbpfError::NotLoaded` when invoked.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EbpfHealth {
    Healthy,
    Unavailable {
        stage: EbpfFailStage,
        category: EbpfFailCategory,
        /// Human-readable explanation, including interface, kernel version,
        /// driver name, and the raw error from the kernel where available.
        reason: String,
    },
}

/// Which stage of eBPF bring-up failed.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfFailStage {
    /// `aya::Ebpf::load(...)` — reading the compiled BPF object file.
    Load,
    /// `aya_log::EbpfLogger::init(...)` — wiring the kernel-to-userspace log channel.
    LoggerInit,
    /// Pipeline program array setup (tail-call dispatch table).
    PipelineSetup,
    /// `EbpfServices::new(...)` — taking map handles for the userspace services.
    MapsBind,
    /// `xdp.attach(ifname, ...)` — attaching the XDP program to the NIC.
    XdpAttach,
    /// AF_XDP socket bind for packet capture.
    AfXdpBind,
}

/// Category of why eBPF bring-up failed. Used by frontend to render
/// targeted guidance (permission vs. driver vs. interface).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfFailCategory {
    /// EPERM / EACCES — process lacks CAP_BPF / CAP_NET_ADMIN / CAP_SYS_ADMIN.
    Permission,
    /// ENODEV / interface name does not resolve.
    InterfaceNotFound,
    /// Interface exists but XDP native/SKB attach refused by driver.
    XdpUnsupported,
    /// AF_XDP bind rejected — driver does not implement AF_XDP on this kernel.
    /// Common case: Intel i350 (igb) on kernel < 6.17.
    AfXdpUnsupported,
    /// ENOMEM / RLIMIT_MEMLOCK exhausted.
    MemlockExhausted,
    /// BPF verifier rejected the program (kernel feature missing or bug).
    VerifierRejected,
    /// BPF object file missing or malformed.
    ObjectNotFound,
    /// Catch-all for errors we could not classify.
    Unknown,
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
