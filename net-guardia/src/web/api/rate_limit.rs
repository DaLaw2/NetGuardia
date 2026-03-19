use actix_web::{web, HttpResponse, Responder, Scope};
use serde::{Deserialize, Serialize};

use crate::core::ebpf::rate_limit::RateLimitConfig;

#[derive(Serialize, Deserialize)]
pub struct RateLimitSettings {
    pub packet_rate: Option<u64>,
    pub syn_rate: Option<u64>,
    pub udp_rate: Option<u64>,
    pub dns_rate: Option<u64>,
    pub window_ns: Option<u64>,
}

pub fn initialize() -> Scope {
    web::scope("/rate-limit")
        .route("/config", web::get().to(get_config))
        .route("/config", web::put().to(set_config))
}

async fn get_config() -> impl Responder {
    HttpResponse::Ok().json(RateLimitSettings {
        packet_rate: Some(common::model::rate_limit::DEFAULT_PACKET_RATE),
        syn_rate: Some(common::model::rate_limit::DEFAULT_SYN_RATE),
        udp_rate: Some(common::model::rate_limit::DEFAULT_UDP_RATE),
        dns_rate: Some(common::model::rate_limit::DEFAULT_DNS_RATE),
        window_ns: Some(common::model::rate_limit::DEFAULT_WINDOW_NS),
    })
}

async fn set_config(
    settings: web::Json<RateLimitSettings>,
    config: web::Data<RateLimitConfig>,
) -> impl Responder {
    let s = settings.into_inner();
    if let Some(v) = s.packet_rate { let _ = config.set_packet_rate(v); }
    if let Some(v) = s.syn_rate { let _ = config.set_syn_rate(v); }
    if let Some(v) = s.udp_rate { let _ = config.set_udp_rate(v); }
    if let Some(v) = s.dns_rate { let _ = config.set_dns_rate(v); }
    if let Some(v) = s.window_ns { let _ = config.set_window_ns(v); }
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}
