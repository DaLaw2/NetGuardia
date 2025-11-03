// net-guardia/src/core/ebpf/health.rs
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sysinfo::{Components, Networks, System};
use tokio::sync::{broadcast, oneshot, RwLock};
use tokio::time::interval;
use tracing::{info, error, warn};

use crate::core::infrastructure::app_config::AppConfig;
use crate::model::error::Error;

pub struct SystemHealth {
    system: RwLock<System>,
    networks: RwLock<Networks>,
    components: RwLock<Components>,
    broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
    ingress_interface: String,
    egress_interface: String,
    // management_interface: String,
}

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
    // pub management: Option<NetworkStats>,
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

impl SystemHealth {
    pub fn new(config: &Arc<AppConfig>) -> Result<Self, Error> {
        let (broadcast_tx, _) = broadcast::channel(100);

        let health = SystemHealth {
            system: RwLock::new(System::new_all()),
            networks: RwLock::new(Networks::new_with_refreshed_list()),
            components: RwLock::new(Components::new_with_refreshed_list()),
            broadcast_tx,
            ingress_interface: config.ingress_ifname.clone(),
            egress_interface: config.egress_ifname.clone(),
            // management_interface: config.management_ifindex.clone(),
        };

        info!(
            "System health monitoring initialized with interfaces: ingress={}, egress={}",
            health.ingress_interface, health.egress_interface
        );

        Ok(health)
    }

    pub async fn run(self: Arc<Self>, monitoring_interval: Duration) -> oneshot::Sender<()> {
        let (sender, mut receiver) = oneshot::channel();
        let health = self.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(monitoring_interval);

            loop {
                tokio::select! {
                    biased;
                    _ = &mut receiver => {
                        break;
                    }
                    _ = interval_timer.tick() => {
                        health.refresh_and_broadcast().await;
                    }
                }
            }
        });

        sender
    }

    async fn refresh_and_broadcast(&self) {
        // Refresh all system information
        self.system.write().await.refresh_all();
        self.networks.write().await.refresh(true);
        self.components.write().await.refresh(true);

        // Collect metrics
        let system = self.system.read().await;
        let networks = self.networks.read().await;
        let components = self.components.read().await;

        let metrics = Self::collect_metrics(
            &system,
            &networks,
            &components,
            &self.ingress_interface,
            &self.egress_interface,
            // &self.management_interface,
        );

        drop(system);
        drop(networks);
        drop(components);

        // Broadcast metrics if there are subscribers
        if self.broadcast_tx.receiver_count() > 0 {
            if let Err(e) = self.broadcast_tx.send(metrics) {
                error!("Failed to broadcast system health metrics: {}", e);
            }
        }
    }

    fn collect_metrics(
        system: &System,
        networks: &Networks,
        components: &Components,
        ingress_interface: &str,
        egress_interface: &str,
        // management_interface: &str,
    ) -> SystemHealthMetrics {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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

        let network_stats = Self::collect_configured_network_stats(
            networks,
            ingress_interface,
            egress_interface,
            // management_interface,
        );

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
        }
    }

    fn collect_system_info(system: &System) -> SystemInfo {
        SystemInfo {
            kernel_version: System::kernel_version(),
            os_name: System::name(),
            os_version: System::os_version(),
            architecture: std::env::consts::ARCH.to_string(),
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
        // management_interface: &str,
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
        // let management = create_network_stats(management_interface);

        if ingress.is_none() {
            warn!("Ingress interface '{}' not found", ingress_interface);
        }
        if egress.is_none() {
            warn!("Egress interface '{}' not found", egress_interface);
        }
        // if management.is_none() {
        //     warn!("Management interface '{}' not found", management_interface);
        // }

        ConfiguredNetworkStats {
            ingress,
            egress,
            // management,
        }
    }

    pub async fn get_current_metrics(&self) -> SystemHealthMetrics {
        self.system.write().await.refresh_all();
        self.networks.write().await.refresh(true);
        self.components.write().await.refresh(true);

        let system = self.system.read().await;
        let networks = self.networks.read().await;
        let components = self.components.read().await;

        Self::collect_metrics(
            &system,
            &networks,
            &components,
            &self.ingress_interface,
            &self.egress_interface,
            // &self.management_interface,
        )
    }

    pub fn subscribe_to_metrics(&self) -> broadcast::Receiver<SystemHealthMetrics> {
        self.broadcast_tx.subscribe()
    }

    pub async fn is_system_healthy(&self) -> SystemHealthStatus {
        let metrics = self.get_current_metrics().await;

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
            status.warnings.push(format!(
                "High memory usage: {:.1}%",
                metrics.memory_usage.usage_percent
            ));
        }

        if let Some(temp) = metrics.temperature {
            if temp > 80.0 {
                status.overall_healthy = false;
                status
                    .issues
                    .push(format!("High CPU temperature: {:.1}°C", temp));
            } else if temp > 70.0 {
                status
                    .warnings
                    .push(format!("Elevated CPU temperature: {:.1}°C", temp));
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
        // if metrics.network_stats.management.is_none() {
        //     status
        //         .warnings
        //         .push("Management interface not available".to_string());
        // }

        status
    }
}