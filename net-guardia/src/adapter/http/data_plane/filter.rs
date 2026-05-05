use std::net::{IpAddr, SocketAddr};

use actix_web::{HttpResponse, Responder, Scope, web};
use common::model::http_method::HttpMethod;
use serde::Deserialize;

use crate::adapter::http::helpers::ok_or_error;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::interface::protocol_filter::{IpVersion, ProtocolFilterPort};

pub fn initialize() -> Scope {
    web::scope("/filter")
        .service(http_scope())
        .service(ssh_scope())
        .service(dns_scope())
}

#[derive(Deserialize)]
struct DnsDomainsRequest {
    domains: Vec<String>,
}

fn parse_ip_version(path: &str) -> Option<IpVersion> {
    match path {
        "ipv4" => Some(IpVersion::V4),
        "ipv6" => Some(IpVersion::V6),
        _ => None,
    }
}

fn dns_scope() -> Scope {
    web::scope("/dns").service(
        web::scope("/blacklist")
            .route("", web::get().to(get_dns_blacklist))
            .route("", web::put().to(add_dns_blacklist))
            .route("", web::delete().to(remove_dns_blacklist)),
    )
}

async fn get_dns_blacklist(service: web::Data<DnsFilterService>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"domains": service.list_domains()}))
}

async fn add_dns_blacklist(
    payload: web::Json<DnsDomainsRequest>,
    service: web::Data<DnsFilterService>,
) -> impl Responder {
    let domains = payload.into_inner().domains;
    match service.add_domains(&domains).await {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({"added": count})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_dns_blacklist(
    payload: web::Json<DnsDomainsRequest>,
    service: web::Data<DnsFilterService>,
) -> impl Responder {
    let domains = payload.into_inner().domains;
    match service.remove_domains(&domains).await {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({"removed": count})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

fn http_scope() -> Scope {
    web::scope("/http")
        .route("/{version}", web::get().to(get_http_service))
        .route("/{version}", web::put().to(add_http_service))
        .route("/{version}", web::delete().to(remove_http_service))
}

fn ssh_scope() -> Scope {
    web::scope("/ssh")
        .route("/{version}", web::get().to(get_ssh_service))
        .route("/{version}", web::put().to(add_ssh_service))
        .route("/{version}", web::delete().to(remove_ssh_service))
        .service(ssh_whitelist_scope())
        .service(ssh_blacklist_scope())
}

fn ssh_whitelist_scope() -> Scope {
    web::scope("/whitelist")
        .route("/status", web::get().to(is_ssh_white_list_enable))
        .route("/enable", web::post().to(enable_ssh_white_list))
        .route("/disable", web::post().to(disable_ssh_white_list))
        .route("/{version}", web::get().to(get_ssh_white_list))
        .route("/{version}", web::put().to(add_ssh_white_list))
        .route("/{version}", web::delete().to(remove_ssh_white_list))
}

fn ssh_blacklist_scope() -> Scope {
    web::scope("/blacklist")
        .route("/{version}", web::get().to(get_ssh_black_list))
        .route("/{version}", web::put().to(add_ssh_black_list))
        .route("/{version}", web::delete().to(remove_ssh_black_list))
}

async fn get_http_service(path: web::Path<String>, service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    HttpResponse::Ok().json(service.get_http_service(version))
}

async fn add_http_service(
    path: web::Path<String>,
    payload: web::Json<(SocketAddr, Vec<HttpMethod>)>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.add_http_service(version, addr, methods))
}

async fn remove_http_service(
    path: web::Path<String>,
    payload: web::Json<(SocketAddr, Vec<HttpMethod>)>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.remove_http_service(version, addr, methods))
}

async fn get_ssh_service(path: web::Path<String>, service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    HttpResponse::Ok().json(service.get_ssh_service(version))
}

async fn add_ssh_service(
    path: web::Path<String>,
    payload: web::Json<SocketAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.add_ssh_service(version, payload.into_inner()))
}

async fn remove_ssh_service(
    path: web::Path<String>,
    payload: web::Json<SocketAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.remove_ssh_service(version, payload.into_inner()))
}

async fn is_ssh_white_list_enable(service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "enabled": service.is_ssh_white_list_enable(),
    }))
}

async fn enable_ssh_white_list(service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    ok_or_error(service.enable_ssh_white_list())
}

async fn disable_ssh_white_list(service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    ok_or_error(service.disable_ssh_white_list())
}

async fn get_ssh_white_list(path: web::Path<String>, service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    HttpResponse::Ok().json(service.get_ssh_white_list(version))
}

async fn add_ssh_white_list(
    path: web::Path<String>,
    payload: web::Json<IpAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.add_ssh_white_list(version, payload.into_inner()))
}

async fn remove_ssh_white_list(
    path: web::Path<String>,
    payload: web::Json<IpAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.remove_ssh_white_list(version, payload.into_inner()))
}

async fn get_ssh_black_list(path: web::Path<String>, service: web::Data<dyn ProtocolFilterPort>) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    HttpResponse::Ok().json(service.get_ssh_black_list(version))
}

async fn add_ssh_black_list(
    path: web::Path<String>,
    payload: web::Json<IpAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.add_ssh_black_list(version, payload.into_inner()))
}

async fn remove_ssh_black_list(
    path: web::Path<String>,
    payload: web::Json<IpAddr>,
    service: web::Data<dyn ProtocolFilterPort>,
) -> impl Responder {
    let Some(version) = parse_ip_version(&path) else {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid IP version"}));
    };
    ok_or_error(service.remove_ssh_black_list(version, payload.into_inner()))
}
