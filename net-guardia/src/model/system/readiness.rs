/// Per-subsystem readiness state exposed by `/health/ready`.
pub struct ReadinessState {
    pub db_connected: std::sync::atomic::AtomicBool,
    pub ml_model_loaded: std::sync::atomic::AtomicBool,
    pub soar_engine_running: std::sync::atomic::AtomicBool,
    pub ebpf_attached: std::sync::atomic::AtomicBool,
    pub started_at: std::time::Instant,
}

impl ReadinessState {
    pub fn new() -> Self {
        Self {
            db_connected: std::sync::atomic::AtomicBool::new(false),
            ml_model_loaded: std::sync::atomic::AtomicBool::new(false),
            soar_engine_running: std::sync::atomic::AtomicBool::new(false),
            ebpf_attached: std::sync::atomic::AtomicBool::new(false),
            started_at: std::time::Instant::now(),
        }
    }
}
