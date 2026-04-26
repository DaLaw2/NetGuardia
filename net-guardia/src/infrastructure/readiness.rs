use std::sync::atomic::AtomicBool;
use std::time::Instant;

pub struct ReadinessState {
    pub db_connected: AtomicBool,
    pub ml_model_loaded: AtomicBool,
    pub soar_engine_running: AtomicBool,
    pub ebpf_attached: AtomicBool,
    pub started_at: Instant,
}

impl ReadinessState {
    pub fn new() -> Self {
        Self {
            db_connected: AtomicBool::new(false),
            ml_model_loaded: AtomicBool::new(false),
            soar_engine_running: AtomicBool::new(false),
            ebpf_attached: AtomicBool::new(false),
            started_at: Instant::now(),
        }
    }
}
