use actix_web::{HttpResponse, Responder, Scope, web};

use crate::interface::system::health_query::{HealthQuery, SuricataHealthQuery};

pub fn initialize() -> Scope {
    web::scope("/health")
        .route("/metrics", web::get().to(get_current_metrics))
        .route("/status", web::get().to(get_health_status))
        .route("/ebpf", web::get().to(get_ebpf_health))
        .route("/suricata", web::get().to(get_suricata_health))
}

async fn get_current_metrics(health: web::Data<dyn HealthQuery>) -> impl Responder {
    HttpResponse::Ok().json(health.get_current_metrics())
}

async fn get_health_status(health: web::Data<dyn HealthQuery>) -> impl Responder {
    HttpResponse::Ok().json(health.get_health_status())
}

async fn get_ebpf_health(health: web::Data<dyn HealthQuery>) -> impl Responder {
    HttpResponse::Ok().json(health.get_ebpf_health())
}

async fn get_suricata_health(manager: web::Data<dyn SuricataHealthQuery>) -> impl Responder {
    HttpResponse::Ok().json(manager.get_suricata_health())
}
