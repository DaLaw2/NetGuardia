use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;
use sysinfo::{ Components, Disks, Networks, System};
use tokio::sync::{broadcast, mpsc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::time::interval;
use tracing::{error, info};

static SYSTEM_HEALTH_INSTANCE: OnceLock<RwLock<SystemHealth>> = OnceLock::new();

pub struct SystemHealth {
    system: System,
    networks: Networks,
    components: Components,
    broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
    shutdown_tx: mpsc::UnboundedSender<()>,
    monitoring_interval: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemHealthMetrics {
    pub timestamp: u64,
    pub cpu_usage: f32,
    pub memory_usage: MemoryUsage,

    pub network_stats: Vec<NetworkStats>,
    pub load_average: Option<LoadAverage>,
    pub temperature: Option<f32>,
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
    pub async fn initialize(monitoring_interval: Duration) {
        let (broadcast_tx, _) = broadcast::channel(100);
        let (shutdown_tx, shutdown_rx) = mpsc::unbounded_channel();
        
        let system_health = SystemHealth {
            system: System::new_all(),
            networks: Networks::new_with_refreshed_list(),
            components: Components::new_with_refreshed_list(),
            broadcast_tx: broadcast_tx.clone(),
            shutdown_tx,
            monitoring_interval,
        };
        
        SYSTEM_HEALTH_INSTANCE.get_or_init(|| RwLock::new(system_health));
        
        tokio::spawn(async move {
            Self::monitoring_loop(broadcast_tx, shutdown_rx, monitoring_interval).await;
        });
        
        info!("System health monitoring initialized");
    }

    async fn monitoring_loop(
        broadcast_tx: broadcast::Sender<SystemHealthMetrics>,
        mut shutdown_rx: mpsc::UnboundedReceiver<()>,
        monitoring_interval: Duration,
    ) {
        let mut system = System::new_all();
        let mut networks = Networks::new_with_refreshed_list();
        let mut components = Components::new_with_refreshed_list();
        let mut interval_timer = interval(monitoring_interval);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("System health monitoring shutdown requested");
                    break;
                }
                _ = interval_timer.tick() => {
                    system.refresh_all();
                    networks.refresh(true); 
                    components.refresh(true);
                    
                    let metrics = Self::collect_metrics(&system, &networks, &components);
                    
                    if broadcast_tx.receiver_count() > 0 {
                        if let Err(e) = broadcast_tx.send(metrics) {
                            error!("Failed to broadcast system health metrics: {}", e);
                        }
                    }
                }
            }
        }
        
        info!("System health monitoring stopped");
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
    ) -> SystemHealthMetrics {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cpu_usage = system.cpus().iter().map(|cpu| cpu.cpu_usage()).sum::<f32>() 
            / system.cpus().len() as f32;

        let memory_usage = MemoryUsage {
            total: system.total_memory(),
            used: system.used_memory(),
            available: system.available_memory(),
            usage_percent: (system.used_memory() as f32 / system.total_memory() as f32) * 100.0,
            swap_total: system.total_swap(),
            swap_used: system.used_swap(),
        };

        // 網路統計
        let network_stats = networks
            .iter()
            .map(|(interface_name, network)| NetworkStats {
                interface: interface_name.clone(),
                bytes_received: network.total_received(),
                bytes_transmitted: network.total_transmitted(),
                packets_received: network.total_packets_received(),
                packets_transmitted: network.total_packets_transmitted(),
                errors_received: network.total_errors_on_received(),
                errors_transmitted: network.total_errors_on_transmitted(),
            })
            .collect();

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
            cpu_usage,
            memory_usage,
            network_stats,
            load_average,
            temperature,
        }
    }

    pub async fn get_current_metrics() -> SystemHealthMetrics {
        let mut instance = Self::instance_mut().await;
        instance.system.refresh_all();
        instance.networks.refresh(true);
        instance.components.refresh(true);
        Self::collect_metrics(&instance.system, &instance.networks, &instance.components)
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

        // CPU 使用率檢查
        if metrics.cpu_usage > 90.0 {
            status.overall_healthy = false;
            status.issues.push(format!("High CPU usage: {:.1}%", metrics.cpu_usage));
        } else if metrics.cpu_usage > 75.0 {
            status.warnings.push(format!("Moderate CPU usage: {:.1}%", metrics.cpu_usage));
        }

        // 記憶體使用率檢查
        if metrics.memory_usage.usage_percent > 95.0 {
            status.overall_healthy = false;
            status.issues.push(format!("Critical memory usage: {:.1}%", metrics.memory_usage.usage_percent));
        } else if metrics.memory_usage.usage_percent > 80.0 {
            status.warnings.push(format!("High memory usage: {:.1}%", metrics.memory_usage.usage_percent));
        }

        // 溫度檢查
        if let Some(temp) = metrics.temperature {
            if temp > 80.0 {
                status.overall_healthy = false;
                status.issues.push(format!("High CPU temperature: {:.1}°C", temp));
            } else if temp > 70.0 {
                status.warnings.push(format!("Elevated CPU temperature: {:.1}°C", temp));
            }
        }

        status
    }

}