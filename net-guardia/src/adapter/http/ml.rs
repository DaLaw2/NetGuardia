use actix_web::{HttpResponse, Responder, Scope, web};

use crate::core::ml::engine::Engine;

pub fn initialize() -> Scope {
    web::scope("/ml").route("/status", web::get().to(get_status))
}

async fn get_status(engine: web::Data<Engine>) -> impl Responder {
    let trackers = engine.trackers();
    let num_trackers = trackers.len();
    let total_flows: usize = trackers.iter().map(|t| t.lock().flow_count()).sum();
    let has_traffic_logger = engine.has_traffic_logger();

    HttpResponse::Ok().json(serde_json::json!({
        "active": true,
        "mode": if has_traffic_logger { "traffic_logging" } else { "inference" },
        "num_trackers": num_trackers,
        "total_flows": total_flows,
        "inference_interval_secs": engine.inference_interval_secs(),
    }))
}
