use std::env::consts;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use macros::log;
use sysinfo::{Components, Disks, Networks, System};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::interval;

use crate::common::error::Error;
use crate::common::log::health::Health;
use crate::domain::common::config::AppConfig;
use crate::domain::common::system::health::{
    ConfiguredNetworkStats, CpuCoreInfo, CpuDetails, EbpfHealth, LoadAverage, MemoryUsage, NetworkStats,
    SystemHealthMetrics, SystemHealthStatus, SystemInfo,
};
use crate::interface::system::health_query::HealthQuery;

pub struct SystemHealth {
    config: Arc<ArcSwap<AppConfig>>,
    metrics: Arc<ArcSwap<SystemHealthMetrics>>,
    broadcast_tx: broadcast::Sender<Arc<SystemHealthMetrics>>,
    ingress_interface: String,
    egress_interface: String,
    ebpf_health: Arc<ArcSwap<EbpfHealth>>,
    cached_disk: Arc<ArcSwap<Option<(f32, f64)>>>,
}

impl SystemHealth {
    pub fn new(config: Arc<ArcSwap<AppConfig>>, ebpf_health: Arc<ArcSwap<EbpfHealth>>) -> Result<Self, Error> {
        let cfg = config.load();
        let (broadcast_tx, _) = broadcast::channel(cfg.health.broadcast_channel_capacity.max(1));
        let ingress_interface = cfg.ebpf.ingress_ifname.clone();
        let egress_interface = cfg.ebpf.egress_ifname.clone();
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

        let cached_disk = Arc::new(ArcSwap::from_pointee(Self::probe_disk_usage()));

        Ok(SystemHealth {
            config,
            metrics: Arc::new(ArcSwap::from_pointee(initial)),
            broadcast_tx,
            ingress_interface,
            egress_interface,
            ebpf_health,
            cached_disk,
        })
    }

    pub async fn run(self: Arc<Self>, monitoring_interval: Duration) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (sender, mut receiver) = oneshot::channel();
        let metrics = self.metrics.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let ingress_interface = self.ingress_interface.clone();
        let egress_interface = self.egress_interface.clone();
        let ebpf_health = self.ebpf_health.clone();
        let cached_disk = self.cached_disk.clone();

        let handle = tokio::spawn(async move {
            let mut system = System::new_all();
            let mut networks = Networks::new_with_refreshed_list();
            let mut components = Components::new_with_refreshed_list();
            let mut interval_timer = interval(monitoring_interval);
            let mut disk_refresh_counter: u32 = 0;
            const DISK_REFRESH_EVERY: u32 = 6;

            loop {
                tokio::select! {
                    biased;
                    _ = &mut receiver => break,
                    _ = interval_timer.tick() => {
                        system.refresh_all();
                        networks.refresh(true);
                        components.refresh(true);

                        disk_refresh_counter += 1;
                        if disk_refresh_counter >= DISK_REFRESH_EVERY {
                            disk_refresh_counter = 0;
                            cached_disk.store(Arc::new(Self::probe_disk_usage()));
                        }

                        let snapshot = Self::collect_metrics(
                            &system,
                            &networks,
                            &components,
                            &ingress_interface,
                            &egress_interface,
                            (**ebpf_health.load()).clone(),
                        );

                        let snapshot = Arc::new(snapshot);
                        metrics.store(Arc::clone(&snapshot));

                        if broadcast_tx.receiver_count() > 0
                            && let Err(e) = broadcast_tx.send(snapshot)
                        {
                            log!(Health::BroadcastFailed(e.to_string()));
                        }
                    }
                }
            }
        });

        (sender, handle)
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
        let uptime_seconds = timestamp.saturating_sub(boot_time);

        let system_info = Self::collect_system_info(system);
        let cpu_details = Self::collect_cpu_details(system);

        let memory_usage = MemoryUsage {
            total: system.total_memory(),
            used: system.used_memory(),
            available: system.available_memory(),
            usage_percent: usage_percent(system.used_memory(), system.total_memory()),
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

        let cpu_usage = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() / cpus.len() as f32
        };

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

    pub fn subscribe_to_metrics(&self) -> broadcast::Receiver<Arc<SystemHealthMetrics>> {
        self.broadcast_tx.subscribe()
    }

    pub fn is_system_healthy(&self) -> SystemHealthStatus {
        let metrics = self.get_current_metrics();
        let h = &self.config.load().health;

        let mut status = SystemHealthStatus {
            overall_healthy: true,
            issues: Vec::new(),
            warnings: Vec::new(),
        };

        if metrics.cpu_details.cpu_usage > h.cpu_issue_percent {
            status.overall_healthy = false;
            status
                .issues
                .push(format!("High CPU usage: {:.1}%", metrics.cpu_details.cpu_usage));
        } else if metrics.cpu_details.cpu_usage > h.cpu_warn_percent {
            status
                .warnings
                .push(format!("Moderate CPU usage: {:.1}%", metrics.cpu_details.cpu_usage));
        }

        if metrics.memory_usage.usage_percent > h.mem_issue_percent {
            status.overall_healthy = false;
            status.issues.push(format!(
                "Critical memory usage: {:.1}%",
                metrics.memory_usage.usage_percent
            ));
        } else if metrics.memory_usage.usage_percent > h.mem_warn_percent {
            status
                .warnings
                .push(format!("High memory usage: {:.1}%", metrics.memory_usage.usage_percent));
        }

        if let Some(temp) = metrics.temperature {
            if temp > h.temp_issue_celsius {
                status.overall_healthy = false;
                status.issues.push(format!("High CPU temperature: {:.1}°C", temp));
            } else if temp > h.temp_warn_celsius {
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

        let disk_usage = **self.cached_disk.load();
        if let Some((usage_percent, available_gb)) = disk_usage {
            if usage_percent > h.disk_issue_percent {
                status.overall_healthy = false;
                status.issues.push(format!(
                    "Critical disk usage: {:.1}% (only {:.1} GB free). Traffic logging paused.",
                    usage_percent, available_gb
                ));
            } else if usage_percent > h.disk_warn_percent {
                status.warnings.push(format!(
                    "High disk usage: {:.1}% ({:.1} GB free)",
                    usage_percent, available_gb
                ));
            }
        }

        status
    }

    fn probe_disk_usage() -> Option<(f32, f64)> {
        let disks = Disks::new_with_refreshed_list();
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

fn usage_percent(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (used as f32 / total as f32) * 100.0
    }
}

impl HealthQuery for SystemHealth {
    fn get_current_metrics(&self) -> SystemHealthMetrics {
        SystemHealth::get_current_metrics(self)
    }

    fn get_health_status(&self) -> SystemHealthStatus {
        self.is_system_healthy()
    }

    fn get_ebpf_health(&self) -> EbpfHealth {
        (**self.ebpf_health.load()).clone()
    }

    fn subscribe_to_metrics(&self) -> broadcast::Receiver<Arc<SystemHealthMetrics>> {
        SystemHealth::subscribe_to_metrics(self)
    }
}

#[cfg(test)]
mod tests {
    use super::usage_percent;

    #[test]
    fn usage_percent_returns_zero_when_total_is_zero() {
        assert_eq!(usage_percent(42, 0), 0.0);
    }

    #[test]
    fn usage_percent_calculates_used_fraction() {
        assert_eq!(usage_percent(25, 100), 25.0);
    }
}
