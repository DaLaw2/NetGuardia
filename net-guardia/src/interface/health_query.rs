use crate::domain::common::system::health::SystemHealthMetrics;

pub trait HealthQuery: Send + Sync {
    fn get_current_metrics(&self) -> SystemHealthMetrics;
}
