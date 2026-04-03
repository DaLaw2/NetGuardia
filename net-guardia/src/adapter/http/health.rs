use actix_web::{HttpResponse, Responder, Scope, web};

use crate::infrastructure::health::SystemHealth;

pub fn initialize() -> Scope {
    web::scope("/health")
        .route("/metrics", web::get().to(get_current_metrics))
        .route("/status", web::get().to(get_health_status))
}

async fn get_current_metrics(health: web::Data<SystemHealth>) -> impl Responder {
    let metrics = health.get_current_metrics().await;
    HttpResponse::Ok().json(metrics)
}

async fn get_health_status(health: web::Data<SystemHealth>) -> impl Responder {
    let status = health.is_system_healthy().await;
    HttpResponse::Ok().json(status)
}
