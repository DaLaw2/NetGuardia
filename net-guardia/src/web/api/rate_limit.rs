use actix_web::{web, HttpResponse, Responder, Scope};
use serde::{Deserialize, Serialize};
use common::define::setting::*;

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

async fn get_config(
    config: web::Data<RateLimitConfig>,
) -> impl Responder {
    HttpResponse::Ok().json(RateLimitSettings {
        packet_rate: Some(config.get_packet_rate().unwrap_or(DEFAULT_PACKET_RATE)),
        syn_rate: Some(config.get_syn_rate().unwrap_or(DEFAULT_SYN_RATE)),
        udp_rate: Some(config.get_udp_rate().unwrap_or(DEFAULT_UDP_RATE)),
        dns_rate: Some(config.get_dns_rate().unwrap_or(DEFAULT_DNS_RATE)),
        window_ns: Some(config.get_window_ns().unwrap_or(DEFAULT_WINDOW_NS)),
    })
}

async fn set_config(
    settings: web::Json<RateLimitSettings>,
    config: web::Data<RateLimitConfig>,
) -> impl Responder {
    let s = settings.into_inner();
    if let Some(v) = s.packet_rate {
        if let Err(e) = config.set_packet_rate(v) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }
    if let Some(v) = s.syn_rate {
        if let Err(e) = config.set_syn_rate(v) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }
    if let Some(v) = s.udp_rate {
        if let Err(e) = config.set_udp_rate(v) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }
    if let Some(v) = s.dns_rate {
        if let Err(e) = config.set_dns_rate(v) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }
    if let Some(v) = s.window_ns {
        if let Err(e) = config.set_window_ns(v) {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}
