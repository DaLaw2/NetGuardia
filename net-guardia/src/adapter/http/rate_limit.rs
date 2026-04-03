use actix_web::{HttpResponse, Responder, Scope, web};
use common::define::setting::*;

use crate::core::rate_limit_service::RateLimitService;
use crate::model::system::rate_limit_settings::RateLimitSettings;

pub fn initialize() -> Scope {
    web::scope("/rate-limit")
        .route("/config", web::get().to(get_config))
        .route("/config", web::put().to(set_config))
}

async fn get_config(service: web::Data<RateLimitService>) -> impl Responder {
    HttpResponse::Ok().json(RateLimitSettings {
        packet_rate: Some(service.config().get_packet_rate().unwrap_or(DEFAULT_PACKET_RATE)),
        syn_rate: Some(service.config().get_syn_rate().unwrap_or(DEFAULT_SYN_RATE)),
        udp_rate: Some(service.config().get_udp_rate().unwrap_or(DEFAULT_UDP_RATE)),
        dns_rate: Some(service.config().get_dns_rate().unwrap_or(DEFAULT_DNS_RATE)),
        window_ns: Some(service.config().get_window_ns().unwrap_or(DEFAULT_WINDOW_NS)),
    })
}

async fn set_config(settings: web::Json<RateLimitSettings>, service: web::Data<RateLimitService>) -> impl Responder {
    match service.update(&settings.into_inner()) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"status": "ok"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
