use crate::model::health::{SystemHealthMetrics, SystemHealthStatus};
use async_trait::async_trait;

/// Port for system health monitoring.
/// Adapters: sysinfo-based (current)
#[async_trait]
pub trait HealthPort: Send + Sync {
    async fn get_metrics(&self) -> SystemHealthMetrics;
    async fn is_healthy(&self) -> SystemHealthStatus;
}
