use std::sync::Arc;

use actix_web::{HttpResponse, Responder, Scope, web};

use crate::core::ml::adapter::ModelSourceState;
use crate::core::ml::engine::Engine;
use crate::core::ml::inference::Inference;

pub fn initialize() -> Scope {
    web::scope("/ml")
        .route("/status", web::get().to(get_status))
        .route("/models/current", web::get().to(get_current_model))
        .route("/models/current", web::delete().to(delete_current_model))
}

async fn get_status(engine: web::Data<Engine>) -> impl Responder {
    let trackers = engine.trackers();
    let num_trackers = trackers.len();
    let total_flows: usize = trackers.iter().map(|t| t.flow_count()).sum();
    let has_traffic_logger = engine.has_traffic_logger();

    HttpResponse::Ok().json(serde_json::json!({
        "active": true,
        "mode": if has_traffic_logger { "traffic_logging" } else { "inference" },
        "num_trackers": num_trackers,
        "total_flows": total_flows,
        "inference_interval_secs": engine.inference_interval_secs(),
    }))
}

/// `GET /api/ml/models/current` — wire-format snapshot of the ML source
/// state the dashboard's ML Status panel renders.
async fn get_current_model(inference: web::Data<Arc<Inference>>) -> impl Responder {
    let status = inference.current_status();
    let label = if status.is_active() {
        "active"
    } else if status.is_dormant() {
        "dormant"
    } else {
        "error"
    };
    HttpResponse::Ok().json(serde_json::json!({
        "label": label,
        "status": status,
    }))
}

/// `DELETE /api/ml/models/current` — admin action: force the ML source back
/// to dormant. No-op when already dormant so the client can retry idempotently.
async fn delete_current_model(inference: web::Data<Arc<Inference>>) -> impl Responder {
    if inference.current_status().is_dormant() {
        return HttpResponse::Ok().json(serde_json::json!({
            "already_dormant": true,
        }));
    }
    inference.swap_state(ModelSourceState::Dormant);
    HttpResponse::Ok().json(serde_json::json!({
        "already_dormant": false,
    }))
}
