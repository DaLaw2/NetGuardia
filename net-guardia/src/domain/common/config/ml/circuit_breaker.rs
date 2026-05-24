use macros::config_settings;

use crate::common::error::Error;
use crate::domain::common::config::require_config_field;

#[config_settings(section = "ml")]
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    #[setting(key = "ml_circuit_breaker_threshold", default = "5")]
    pub threshold: u32,
    #[setting(key = "ml_circuit_breaker_window_secs", default = "60")]
    pub window_secs: u64,
    #[setting(key = "ml_circuit_breaker_cooldown_secs", default = "120")]
    pub cooldown_secs: u64,
}

impl CircuitBreakerConfig {
    pub fn validate(&self) -> Result<(), Error> {
        require_config_field(self.threshold > 0, "ml.circuit_breaker.threshold")?;
        require_config_field(self.window_secs > 0, "ml.circuit_breaker.window_secs")
    }
}
