use serde::Serialize;

#[derive(Serialize)]
pub struct XdpModes {
    pub ingress_mode: String,
    pub egress_mode: String,
}

pub trait XdpModeQuery: Send + Sync {
    fn get_xdp_modes(&self) -> XdpModes;
}

pub trait BootTimeQuery: Send + Sync {
    fn boot_time_ns(&self) -> u64;
}

pub trait LogLevelControl: Send + Sync {
    fn current_level(&self) -> String;
    fn set_level(&self, level: &str) -> Result<String, String>;
}

pub trait SystemCommandPort: Send + Sync {
    fn trigger_shutdown(&self) -> bool;
    fn trigger_restart(&self) -> bool;
}
