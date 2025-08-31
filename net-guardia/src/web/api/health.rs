// src/web/api/system_health.rs
use crate::core::health::SystemHealth;
use crate::web::utils::health_websocket;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/health")
        .service(get_current_metrics)
        .service(get_health_status)
        .service(websocket_metrics)
}

#[get("/metrics")]
async fn get_current_metrics() -> impl Responder {
    let metrics = SystemHealth::get_current_metrics().await;
    HttpResponse::Ok().json(metrics)
}

#[get("/status")]
async fn get_health_status() -> impl Responder {
    let status = SystemHealth::is_system_healthy().await;
    HttpResponse::Ok().json(status)
}

#[get("/websocket/system_health")]
async fn websocket_metrics(req: HttpRequest, body: web::Payload) -> impl Responder {
    let broadcast_rx = SystemHealth::subscribe_to_metrics().await;
    match health_websocket::websocket_system_health(req, body, broadcast_rx).await {
        Ok(response) => response,
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err))
        }
    }
}
