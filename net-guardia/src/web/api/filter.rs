use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use actix_web::{web, HttpResponse, Responder, Scope};
use common::model::http_method::HttpMethod;
use serde::Deserialize;

use crate::core::ebpf::dns_filter::DnsFilter;
use crate::core::ebpf::protocol_filter::ProtocolFilter;

/// Convert a fallible result into an Ok (200) or InternalServerError (500) response.
fn ok_or_error<T, E: fmt::Display>(result: Result<T, E>) -> HttpResponse {
    match result {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn initialize() -> Scope {
    web::scope("/filter")
        .service(http_scope())
        .service(ssh_scope())
        .service(dns_scope())
}

#[derive(Deserialize)]
struct DnsDomainsPayload {
    domains: Vec<String>,
}

fn dns_scope() -> Scope {
    web::scope("/dns")
        .service(
            web::scope("/blacklist")
                .route("", web::get().to(get_dns_blacklist))
                .route("", web::put().to(add_dns_blacklist))
                .route("", web::delete().to(remove_dns_blacklist))
        )
}

const MAX_DNS_DOMAINS_PER_REQUEST: usize = 1000;

async fn get_dns_blacklist(service: web::Data<DnsFilter>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"domains": service.list_domains()}))
}

async fn add_dns_blacklist(
    payload: web::Json<DnsDomainsPayload>,
    service: web::Data<DnsFilter>,
) -> impl Responder {
    let domains = payload.into_inner().domains;
    if domains.len() > MAX_DNS_DOMAINS_PER_REQUEST {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": format!("too many domains (max {})", MAX_DNS_DOMAINS_PER_REQUEST)}));
    }
    for domain in &domains {
        if let Err(e) = service.add_domain(domain) {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"added": domains.len()}))
}

async fn remove_dns_blacklist(
    payload: web::Json<DnsDomainsPayload>,
    service: web::Data<DnsFilter>,
) -> impl Responder {
    let domains = payload.into_inner().domains;
    for domain in &domains {
        if let Err(e) = service.remove_domain(domain) {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    }
    HttpResponse::Ok().json(serde_json::json!({"removed": domains.len()}))
}

fn http_scope() -> Scope {
    web::scope("/http")
        .route("/ipv4", web::get().to(get_ipv4_http_service))
        .route("/ipv6", web::get().to(get_ipv6_http_service))
        .route("/ipv4", web::put().to(add_ipv4_http_service))
        .route("/ipv6", web::put().to(add_ipv6_http_service))
        .route("/ipv4", web::delete().to(remove_ipv4_http_service))
        .route("/ipv6", web::delete().to(remove_ipv6_http_service))
}

fn ssh_scope() -> Scope {
    web::scope("/ssh")
        .route("/ipv4", web::get().to(get_ipv4_ssh_service))
        .route("/ipv6", web::get().to(get_ipv6_ssh_service))
        .route("/ipv4", web::put().to(add_ipv4_ssh_service))
        .route("/ipv6", web::put().to(add_ipv6_ssh_service))
        .route("/ipv4", web::delete().to(remove_ipv4_ssh_service))
        .route("/ipv6", web::delete().to(remove_ipv6_ssh_service))
        .service(ssh_whitelist_scope())
        .service(ssh_blacklist_scope())
}

fn ssh_whitelist_scope() -> Scope {
    web::scope("/whitelist")
        .route("/status", web::get().to(is_ssh_white_list_enable))
        .route("/enable", web::post().to(enable_ssh_white_list))
        .route("/disable", web::post().to(disable_ssh_white_list))
        .route("/ipv4", web::get().to(get_ipv4_ssh_white_list))
        .route("/ipv6", web::get().to(get_ipv6_ssh_white_list))
        .route("/ipv4", web::put().to(add_ipv4_ssh_white_list))
        .route("/ipv6", web::put().to(add_ipv6_ssh_white_list))
        .route("/ipv4", web::delete().to(remove_ipv4_ssh_white_list))
        .route("/ipv6", web::delete().to(remove_ipv6_ssh_white_list))
}

fn ssh_blacklist_scope() -> Scope {
    web::scope("/blacklist")
        .route("/ipv4", web::get().to(get_ipv4_ssh_black_list))
        .route("/ipv6", web::get().to(get_ipv6_ssh_black_list))
        .route("/ipv4", web::put().to(add_ipv4_ssh_black_list))
        .route("/ipv6", web::put().to(add_ipv6_ssh_black_list))
        .route("/ipv4", web::delete().to(remove_ipv4_ssh_black_list))
        .route("/ipv6", web::delete().to(remove_ipv6_ssh_black_list))
}

// --- HTTP service handlers ---

async fn get_ipv4_http_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv4_http_service().await)
}

async fn get_ipv6_http_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv6_http_service().await)
}

async fn add_ipv4_http_service(payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>, service: web::Data<ProtocolFilter>) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.add_ipv4_http_service(addr, methods).await)
}

async fn add_ipv6_http_service(payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>, service: web::Data<ProtocolFilter>) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.add_ipv6_http_service(addr, methods).await)
}

async fn remove_ipv4_http_service(payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>, service: web::Data<ProtocolFilter>) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.remove_ipv4_http_service(addr, methods).await)
}

async fn remove_ipv6_http_service(payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>, service: web::Data<ProtocolFilter>) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    ok_or_error(service.remove_ipv6_http_service(addr, methods).await)
}

// --- SSH service handlers ---

async fn get_ipv4_ssh_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv4_ssh_service().await)
}

async fn get_ipv6_ssh_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv6_ssh_service().await)
}

async fn add_ipv4_ssh_service(ip_addr: web::Json<SocketAddrV4>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv4_ssh_service(ip_addr.into_inner()).await)
}

async fn add_ipv6_ssh_service(ip_addr: web::Json<SocketAddrV6>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv6_ssh_service(ip_addr.into_inner()).await)
}

async fn remove_ipv4_ssh_service(ip_addr: web::Json<SocketAddrV4>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv4_ssh_service(ip_addr.into_inner()).await)
}

async fn remove_ipv6_ssh_service(ip_addr: web::Json<SocketAddrV6>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv6_ssh_service(ip_addr.into_inner()).await)
}

// --- SSH whitelist handlers ---

async fn is_ssh_white_list_enable(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.is_ssh_white_list_enable().await)
}

async fn enable_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.enable_ssh_white_list().await)
}

async fn disable_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.disable_ssh_white_list().await)
}

async fn get_ipv4_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv4_ssh_white_list().await)
}

async fn get_ipv6_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv6_ssh_white_list().await)
}

async fn add_ipv4_ssh_white_list(ip_addr: web::Json<Ipv4Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv4_ssh_white_list(ip_addr.into_inner()).await)
}

async fn add_ipv6_ssh_white_list(ip_addr: web::Json<Ipv6Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv6_ssh_white_list(ip_addr.into_inner()).await)
}

async fn remove_ipv4_ssh_white_list(ip_addr: web::Json<Ipv4Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv4_ssh_white_list(ip_addr.into_inner()).await)
}

async fn remove_ipv6_ssh_white_list(ip_addr: web::Json<Ipv6Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv6_ssh_white_list(ip_addr.into_inner()).await)
}

// --- SSH blacklist handlers ---

async fn get_ipv4_ssh_black_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv4_ssh_black_list().await)
}

async fn get_ipv6_ssh_black_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    HttpResponse::Ok().json(service.get_ipv6_ssh_black_list().await)
}

async fn add_ipv4_ssh_black_list(ip_addr: web::Json<Ipv4Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv4_ssh_black_list(ip_addr.into_inner()).await)
}

async fn add_ipv6_ssh_black_list(ip_addr: web::Json<Ipv6Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.add_ipv6_ssh_black_list(ip_addr.into_inner()).await)
}

async fn remove_ipv4_ssh_black_list(ip_addr: web::Json<Ipv4Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv4_ssh_black_list(ip_addr.into_inner()).await)
}

async fn remove_ipv6_ssh_black_list(ip_addr: web::Json<Ipv6Addr>, service: web::Data<ProtocolFilter>) -> impl Responder {
    ok_or_error(service.remove_ipv6_ssh_black_list(ip_addr.into_inner()).await)
}
