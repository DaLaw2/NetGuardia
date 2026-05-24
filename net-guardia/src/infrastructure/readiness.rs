use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Instant;

use crate::interface::system::http_runtime::{ReadinessQuery, ReadySnapshot, ReadySubsystems};

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

impl ReadinessQuery for ReadinessState {
    fn snapshot(&self, ready: bool) -> ReadySnapshot {
        ReadySnapshot {
            ready,
            subsystems: ReadySubsystems {
                db_connected: self.db_connected.load(SeqCst),
                ml_model_loaded: self.ml_model_loaded.load(SeqCst),
                soar_engine_running: self.soar_engine_running.load(SeqCst),
                ebpf_attached: self.ebpf_attached.load(SeqCst),
            },
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }
}
