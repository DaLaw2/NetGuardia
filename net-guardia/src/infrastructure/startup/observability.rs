use std::sync::Arc;

use crate::common::error::Error;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::startup::{FoundationRuntime, ObservabilityRuntime};
use crate::infrastructure::suricata_manager::SuricataManager;

pub fn build_observability(foundation: &FoundationRuntime) -> Result<ObservabilityRuntime, Error> {
    let health = Arc::new(SystemHealth::new(
        foundation.app_config.clone(),
        foundation.ebpf_health.clone(),
    )?);
    let suricata_manager = SuricataManager::new(foundation.app_config.clone());
    Ok(ObservabilityRuntime {
        health,
        suricata_manager,
    })
}
