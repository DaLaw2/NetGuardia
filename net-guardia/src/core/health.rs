use std::sync::OnceLock;
use std::time::Duration;

use macros::log;
use sysinfo::{Components, Networks, System};
use tokio::sync::{broadcast, mpsc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::time::interval;

use crate::core::app_config::AppConfig;
use crate::model::error::misc::MiscError;
use crate::model::healthy::*;

static SYSTEM_HEALTH_INSTANCE: OnceLock<RwLock<SystemHealth>> = OnceLock::new();

pub struct SystemHealth {
    system: System,
    networks: Networks,
    components: Components,
    broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
    shutdown_tx: mpsc::UnboundedSender<()>,
    ingress_interface: String,
    egress_interface: String,
    management_interface: String,
}

impl SystemHealth {
    pub async fn initialize(monitoring_interval: Duration) {
        let (broadcast_tx, _) = broadcast::channel(100);
        let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();

        let config = AppConfig::now().await;

        let system_health = SystemHealth {
            system: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            components: Components::new_with_refreshed_list(),
            broadcast_tx: broadcast_tx.clone(),
            shutdown_tx,
            ingress_interface: config.ingress_ifindex.clone(),
            egress_interface: config.egress_ifindex.clone(),
            management_interface: config.management_ifindex.clone(),
        };

        SYSTEM_HEALTH_INSTANCE.get_or_init(|| RwLock::new(system_health));

        let ingress_interface = config.ingress_ifindex;
        let egress_interface = config.egress_ifindex;
        let management_interface = config.management_ifindex;

        tokio::spawn(async move {
            Self::monitoring_loop(
                broadcast_tx,
                shutdown_rx,
                monitoring_interval,
                ingress_interface,
                egress_interface,
                management_interface,
            )
            .await;
        });
    }

    async fn monitoring_loop(
        broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
        mut shutdown_rx: mpsc::UnboundedReceiver<()>,
        monitoring_interval: Duration,
        ingress_interface: String,
        egress_interface: String,
        management_interface: String,
    ) {
        let mut system = System::new_all();
        let mut networks = Networks::new_with_refreshed_list();
        let mut components = Components::new_with_refreshed_list();
        let mut interval_timer = interval(monitoring_interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                _ = interval_timer.tick() => {
                    system.refresh_all();
                    networks.refresh(true);
                    components.refresh(true);

                    let metrics = Self::collect_metrics(
                        &system,
                        &networks,
                        &components,
                        &ingress_interface,
                        &egress_interface,
                        &management_interface,
                    );

                    if broadcast_tx.receiver_count() > 0 {
                        if let Err(err) = broadcast_tx.send(metrics) {
                            log!(MiscError::SendMessageError(err))
                        }
                    }
                }
            }
        }
    }

    pub async fn instance() -> RwLockReadGuard<'static, SystemHealth> {
        let instance = SYSTEM_HEALTH_INSTANCE.get().unwrap();
        instance.read().await
    }

    pub async fn instance_mut() -> RwLockWriteGuard<'static, SystemHealth> {
        let instance = SYSTEM_HEALTH_INSTANCE.get().unwrap();
        instance.write().await
    }

    fn collect_metrics(
        system: &System,
        networks: &Networks,
        components: &Components,
        ingress_interface: &str,
        egress_interface: &str,
        management_interface: &str,
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

        let network_stats =
            Self::collect_configured_network_stats(networks, ingress_interface, egress_interface, management_interface);

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
        management_interface: &str,
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
        let management = create_network_stats(management_interface);

        if ingress.is_none() {
            log!(MiscError::NetworkInterfaceNotFound(ingress_interface));
        }
        if egress.is_none() {
            log!(MiscError::NetworkInterfaceNotFound(egress_interface));
        }
        if management.is_none() {
            log!(MiscError::NetworkInterfaceNotFound(management_interface));
        }

        ConfiguredNetworkStats {
            ingress,
            egress,
            management,
        }
    }

    pub async fn get_current_metrics() -> SystemHealthMetrics {
        let mut instance = Self::instance_mut().await;
        instance.system.refresh_all();
        instance.networks.refresh(true);
        instance.components.refresh(true);

        Self::collect_metrics(
            &instance.system,
            &instance.networks,
            &instance.components,
            &instance.ingress_interface,
            &instance.egress_interface,
            &instance.management_interface,
        )
    }

    pub async fn subscribe_to_metrics() -> broadcast::Receiver<SystemHealthMetrics> {
        let instance = Self::instance().await;
        instance.broadcast_tx.subscribe()
    }

    pub async fn shutdown() {
        if let Ok(instance) = SYSTEM_HEALTH_INSTANCE.get().unwrap().try_read() {
            let _ = instance.shutdown_tx.send(());
        }
    }

    pub async fn is_system_healthy() -> SystemHealthStatus {
        let metrics = Self::get_current_metrics().await;

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
        if metrics.network_stats.management.is_none() {
            status.warnings.push("Management interface not available".to_string());
        }

        status
    }
}
