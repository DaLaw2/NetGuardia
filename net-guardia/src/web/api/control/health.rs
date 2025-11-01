use actix_web::{get, web, HttpRequest, HttpResponse, Responder, Scope};

use crate::core::ebpf::health::SystemHealth;
use crate::web::websocket::health_websocket;

pub fn initialize() -> Scope {
    web::scope("/health")
        .service(get_current_metrics)
        .service(get_health_status)
        .service(websocket_metrics)
}

#[get("/metrics")]
async fn get_current_metrics(health: web::Data<SystemHealth>) -> impl Responder {
    let metrics = health.get_current_metrics().await;
    HttpResponse::Ok().json(metrics)
}

#[get("/status")]
async fn get_health_status(health: web::Data<SystemHealth>) -> impl Responder {
    let status = health.is_system_healthy().await;
    HttpResponse::Ok().json(status)
}

#[get("/websocket/metrics")]
async fn websocket_metrics(
    req: HttpRequest,
    stream: web::Payload,
    health: web::Data<SystemHealth>,
) -> impl Responder {
    match health_websocket::websocket_system_health(req, stream, health).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err)),
    }
}