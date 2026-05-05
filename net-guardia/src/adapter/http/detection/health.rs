use actix_web::{HttpResponse, Responder, Scope, web};

use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::suricata_manager::SuricataManager;

pub fn initialize() -> Scope {
    web::scope("/health")
        .route("/metrics", web::get().to(get_current_metrics))
        .route("/status", web::get().to(get_health_status))
        .route("/ebpf", web::get().to(get_ebpf_health))
        .route("/suricata", web::get().to(get_suricata_health))
}

async fn get_current_metrics(health: web::Data<SystemHealth>) -> impl Responder {
    let metrics = health.get_current_metrics();
    HttpResponse::Ok().json(metrics)
}

async fn get_health_status(health: web::Data<SystemHealth>) -> impl Responder {
    let status = health.is_system_healthy();
    HttpResponse::Ok().json(status)
}

async fn get_ebpf_health(health: web::Data<SystemHealth>) -> impl Responder {
    let ebpf = (**health.ebpf_health().load()).clone();
    HttpResponse::Ok().json(ebpf)
}

async fn get_suricata_health(manager: web::Data<SuricataManager>) -> impl Responder {
    let state = (**manager.health().load()).clone();
    HttpResponse::Ok().json(state)
}
