use actix_web::{web, HttpRequest, HttpResponse, Responder, Scope};

use crate::core::infrastructure::health::SystemHealth;
use crate::core::infrastructure::statistics::FlowStatistics;
use crate::core::ml::alert::MLAlert;
use crate::web::websocket::{alert_websocket, flow_websocket, health_websocket};

pub fn initialize() -> Scope {
    web::scope("/ws")
        .route("/health", web::get().to(health_ws))
        .route("/alerts", web::get().to(alerts_ws))
        .route("/flows", web::get().to(flows_ws))
}

async fn health_ws(
    req: HttpRequest,
    stream: web::Payload,
    health: web::Data<SystemHealth>,
) -> impl Responder {
    match health_websocket::websocket_system_health(req, stream, health).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}

async fn alerts_ws(
    req: HttpRequest,
    stream: web::Payload,
    ai: web::Data<MLAlert>,
) -> impl Responder {
    match alert_websocket::websocket_alert(req, stream, ai).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}

async fn flows_ws(
    req: HttpRequest,
    stream: web::Payload,
    stats: web::Data<FlowStatistics>,
) -> impl Responder {
    match flow_websocket::flow_stats_ws(req, stream, stats).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}
