use serde::Serialize;

#[derive(Serialize)]
pub struct ReadySnapshot {
    pub ready: bool,
    pub subsystems: ReadySubsystems,
    pub uptime_secs: u64,
}

#[derive(Serialize)]
pub struct ReadySubsystems {
    pub db_connected: bool,
    pub ml_model_loaded: bool,
    pub soar_engine_running: bool,
    pub ebpf_attached: bool,
}

pub trait ReadinessQuery: Send + Sync {
    fn snapshot(&self, ready: bool) -> ReadySnapshot;
}
