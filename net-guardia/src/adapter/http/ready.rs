use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;

use actix_web::{HttpResponse, web};

use crate::infrastructure::readiness::ReadinessState;

pub async fn health_ready(ready: web::Data<Arc<AtomicBool>>, state: web::Data<ReadinessState>) -> HttpResponse {
    let is_ready = ready.load(SeqCst);
    let uptime_secs = state.started_at.elapsed().as_secs();

    HttpResponse::Ok().json(serde_json::json!({
        "ready": is_ready,
        "subsystems": {
            "db_connected": state.db_connected.load(SeqCst),
            "ml_model_loaded": state.ml_model_loaded.load(SeqCst),
            "soar_engine_running": state.soar_engine_running.load(SeqCst),
            "ebpf_attached": state.ebpf_attached.load(SeqCst),
        },
        "uptime_secs": uptime_secs,
    }))
}
