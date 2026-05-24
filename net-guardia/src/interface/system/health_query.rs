use std::sync::Arc;

use tokio::sync::broadcast;

use crate::domain::common::system::health::{EbpfHealth, SystemHealthMetrics, SystemHealthStatus};
use crate::domain::detection::suricata_health::SuricataHealth;

pub trait HealthQuery: Send + Sync {
    fn get_current_metrics(&self) -> SystemHealthMetrics;
    fn get_health_status(&self) -> SystemHealthStatus;
    fn get_ebpf_health(&self) -> EbpfHealth;
    fn subscribe_to_metrics(&self) -> broadcast::Receiver<Arc<SystemHealthMetrics>>;
}

pub trait SuricataHealthQuery: Send + Sync {
    fn get_suricata_health(&self) -> SuricataHealth;
}
