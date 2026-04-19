use std::env::consts;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use macros::log;
use sysinfo::{Components, Networks, System};
use tokio::sync::{broadcast, oneshot};
use tokio::time::interval;

use crate::infrastructure::app_config::AppConfig;
use crate::model::error::Error;
use crate::model::log::health::Health;
use crate::model::system::health::{
    ConfiguredNetworkStats, CpuCoreInfo, CpuDetails, EbpfHealth, LoadAverage, MemoryUsage, NetworkStats,
    SystemHealthMetrics, SystemHealthStatus, SystemInfo,
};

/// Lock-free system health.
///
/// A single owner task on the tokio runtime owns the sysinfo handles
/// (`System`, `Networks`, `Components`). It refreshes them on a tick,
/// computes a fresh `SystemHealthMetrics`, publishes the snapshot via
/// `ArcSwap`, and broadcasts to streaming subscribers. Readers
/// (`get_current_metrics`, `is_system_healthy`, HTTP handlers) just
/// `.load()` the `ArcSwap` — no locks crossed, no `await` needed.
pub struct SystemHealth {
    metrics: Arc<ArcSwap<SystemHealthMetrics>>,
    broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
    ingress_interface: String,
    egress_interface: String,
    ebpf_health: Arc<ArcSwap<EbpfHealth>>,
}

impl SystemHealth {
    pub fn new(config: Arc<AppConfig>, ebpf_health: Arc<ArcSwap<EbpfHealth>>) -> Result<Self, Error> {
        let (broadcast_tx, _) = broadcast::channel(100);
        let ingress_interface = config.network.ingress_ifname.clone();
        let egress_interface = config.network.egress_ifname.clone();

        // Bootstrap snapshot so readers don't have to handle a "no metrics yet"
        // case before the refresh task fires for the first time. The
        // `*_with_refreshed_list` constructors already do an initial refresh.
        let system = System::new_all();
        let networks = Networks::new_with_refreshed_list();
        let components = Components::new_with_refreshed_list();
        let initial = Self::collect_metrics(
            &system,
            &networks,
            &components,
            &ingress_interface,
            &egress_interface,
            (**ebpf_health.load()).clone(),
        );

        Ok(SystemHealth {
            metrics: Arc::new(ArcSwap::from_pointee(initial)),
            broadcast_tx,
            ingress_interface,
            egress_interface,
            ebpf_health,
        })
    }

    pub async fn run(self: Arc<Self>, monitoring_interval: Duration) -> oneshot::Sender<()> {
        let (sender, mut receiver) = oneshot::channel();
        let metrics = self.metrics.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let ingress_interface = self.ingress_interface.clone();
        let egress_interface = self.egress_interface.clone();
        let ebpf_health = self.ebpf_health.clone();

        tokio::spawn(async move {
            // Owner task exclusively holds these sysinfo handles, so no locks
            // are needed on the data plane.
            let mut system = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let mut components = Components::new_with_refreshed_list();
            let mut interval_timer = interval(monitoring_interval);

            loop {
                tokio::select! {
                    biased;
                    _ = &mut receiver => break,
                    _ = interval_timer.tick() => {
                        system.refresh_all();
                        networks.refresh(true);
                        components.refresh(true);

                        let snapshot = Self::collect_metrics(
                            &system,
                            &networks,
                            &components,
                            &ingress_interface,
                            &egress_interface,
                            (**ebpf_health.load()).clone(),
                        );

                        metrics.store(Arc::new(snapshot.clone()));

                        if broadcast_tx.receiver_count() > 0
                            && let Err(e) = broadcast_tx.send(snapshot)
                        {
                            log!(Health::BroadcastFailed(e.to_string()));
                        }
                    }
                }
            }
        });

        sender
    }

    fn collect_metrics(
        system: &System,
        networks: &Networks,
        components: &Components,
        ingress_interface: &str,
        egress_interface: &str,
        ebpf: EbpfHealth,
    ) -> SystemHealthMetrics {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let boot_time = System::boot_time();
        let uptime_seconds = timestamp - boot_time;

        let system_info = Self::collect_system_info(system);
        let cpu_details = Self::collect_cpu_details(system);

        let memory_usage = MemoryUsage {
            total: system.total_memory(),
            used: system.used_memory(),
            available: system.available_memory(),
            usage_percent: (system.used_memory() as f32 / system.total_memory() as f32) * 100.0,
            swap_total: system.total_swap(),
            swap_used: system.used_swap(),
        };

        let network_stats = Self::collect_configured_network_stats(networks, ingress_interface, egress_interface);

        let load_average = System::load_average();
        let load_average = if load_average.one != 0.0 || load_average.five != 0.0 || load_average.fifteen != 0.0 {
            Some(LoadAverage {
                one_minute: load_average.one,
                five_minute: load_average.five,
                fifteen_minute: load_average.fifteen,
            })
        } else {
            None
        };

        let temperature = components
            .iter()
            .find(|component| {
                let label = component.label().to_lowercase();
                label.contains("cpu") || label.contains("core") || label.contains("processor")
            })
            .and_then(|component| component.temperature());

        SystemHealthMetrics {
            timestamp,
            boot_time,
            uptime_seconds,
            system_info,
            cpu_details,
            memory_usage,
            network_stats,
            load_average,
            temperature,
            ebpf,
        }
    }

    fn collect_system_info(system: &System) -> SystemInfo {
        SystemInfo {
            kernel_version: System::kernel_version(),
            os_name: System::name(),
            os_version: System::os_version(),
            architecture: consts::ARCH.to_string(),
            total_processes: system.processes().len(),
        }
    }

    fn collect_cpu_details(system: &System) -> CpuDetails {
        let cpus = system.cpus();

        let cpu_usage = cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32;

        let cores: Vec<CpuCoreInfo> = cpus
            .iter()
            .enumerate()
            .map(|(index, cpu)| CpuCoreInfo {
                core_id: index,
                usage_percent: cpu.cpu_usage(),
                frequency: cpu.frequency(),
            })
            .collect();

        let cpu_brand = cpus
            .first()
            .map(|cpu| cpu.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let avg_frequency = if !cores.is_empty() {
            cores.iter().map(|core| core.frequency).sum::<u64>() / cores.len() as u64
        } else {
            0
        };

        CpuDetails {
            cpu_brand,
            core_count: cores.len(),
            cpu_usage,
            cpu_frequency: avg_frequency,
            cores,
        }
    }

    fn collect_configured_network_stats(
        networks: &Networks,
        ingress_interface: &str,
        egress_interface: &str,
    ) -> ConfiguredNetworkStats {
        let create_network_stats = |interface_name: &str| -> Option<NetworkStats> {
            networks.get(interface_name).map(|network| NetworkStats {
                interface: interface_name.to_string(),
                bytes_received: network.total_received(),
                bytes_transmitted: network.total_transmitted(),
                packets_received: network.total_packets_received(),
                packets_transmitted: network.total_packets_transmitted(),
                errors_received: network.total_errors_on_received(),
                errors_transmitted: network.total_errors_on_transmitted(),
            })
        };

        let ingress = create_network_stats(ingress_interface);
        let egress = create_network_stats(egress_interface);

        if ingress.is_none() {
            log!(Health::InterfaceNotFound(
                "Ingress".to_string(),
                ingress_interface.to_string()
            ));
        }
        if egress.is_none() {
            log!(Health::InterfaceNotFound(
                "Egress".to_string(),
                egress_interface.to_string()
            ));
        }
        ConfiguredNetworkStats { ingress, egress }
    }

    pub fn get_current_metrics(&self) -> SystemHealthMetrics {
        (**self.metrics.load()).clone()
    }

    /// Returns a handle to the shared eBPF health state. Consumers (HTTP
    /// handlers, setup wizard, frontend) can read the current eBPF state
    /// without going through the full metrics broadcast.
    pub fn ebpf_health(&self) -> &Arc<ArcSwap<EbpfHealth>> {
        &self.ebpf_health
    }

    pub fn subscribe_to_metrics(&self) -> broadcast::Receiver<SystemHealthMetrics> {
        self.broadcast_tx.subscribe()
    }

    pub fn is_system_healthy(&self) -> SystemHealthStatus {
        let metrics = self.get_current_metrics();

        let mut status = SystemHealthStatus {
            overall_healthy: true,
            issues: Vec::new(),
            warnings: Vec::new(),
        };

        if metrics.cpu_details.cpu_usage > 90.0 {
            status.overall_healthy = false;
            status
                .issues
                .push(format!("High CPU usage: {:.1}%", metrics.cpu_details.cpu_usage));
        } else if metrics.cpu_details.cpu_usage > 75.0 {
            status
                .warnings
                .push(format!("Moderate CPU usage: {:.1}%", metrics.cpu_details.cpu_usage));
        }

        if metrics.memory_usage.usage_percent > 95.0 {
            status.overall_healthy = false;
            status.issues.push(format!(
                "Critical memory usage: {:.1}%",
                metrics.memory_usage.usage_percent
            ));
        } else if metrics.memory_usage.usage_percent > 80.0 {
            status
                .warnings
                .push(format!("High memory usage: {:.1}%", metrics.memory_usage.usage_percent));
        }

        if let Some(temp) = metrics.temperature {
            if temp > 80.0 {
                status.overall_healthy = false;
                status.issues.push(format!("High CPU temperature: {:.1}°C", temp));
            } else if temp > 70.0 {
                status.warnings.push(format!("Elevated CPU temperature: {:.1}°C", temp));
            }
        }

        if metrics.network_stats.ingress.is_none() {
            status.overall_healthy = false;
            status.issues.push("Ingress interface not available".to_string());
        }
        if metrics.network_stats.egress.is_none() {
            status.overall_healthy = false;
            status.issues.push("Egress interface not available".to_string());
        }

        // Disk usage check
        let disk_usage = Self::check_disk_usage();
        if let Some((usage_percent, available_gb)) = disk_usage {
            if usage_percent > 95.0 {
                status.overall_healthy = false;
                status.issues.push(format!(
                    "Critical disk usage: {:.1}% (only {:.1} GB free). Traffic logging paused.",
                    usage_percent, available_gb
                ));
            } else if usage_percent > 90.0 {
                status.warnings.push(format!(
                    "High disk usage: {:.1}% ({:.1} GB free)",
                    usage_percent, available_gb
                ));
            }
        }

        status
    }

    fn check_disk_usage() -> Option<(f32, f64)> {
        use sysinfo::Disks;
        let disks = Disks::new_with_refreshed_list();
        // Find the root disk or the disk containing /opt/netguardia
        for disk in disks.list() {
            let mount = disk.mount_point().to_string_lossy();
            if mount == "/" || mount.starts_with("/opt") {
                let total = disk.total_space() as f64;
                let available = disk.available_space() as f64;
                if total > 0.0 {
                    let usage_percent = ((total - available) / total * 100.0) as f32;
                    let available_gb = available / (1024.0 * 1024.0 * 1024.0);
                    return Some((usage_percent, available_gb));
                }
            }
        }
        None
    }
}
