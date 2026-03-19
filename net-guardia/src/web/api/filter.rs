use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use actix_web::{web, HttpResponse, Responder, Scope};
use common::model::http_method::HttpMethod;

use crate::core::ebpf::protocol_filter::ProtocolFilter;

pub fn initialize() -> Scope {
    web::scope("/filter")
        .service(http_scope())
        .service(ssh_scope())
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
    let list = service.get_ipv4_http_service().await;
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_http_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv6_http_service().await;
    HttpResponse::Ok().json(list)
}

async fn add_ipv4_http_service(
    payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match service.add_ipv4_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_http_service(
    payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match service.add_ipv6_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_http_service(
    payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match service.remove_ipv4_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_http_service(
    payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match service.remove_ipv6_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// --- SSH service handlers ---

async fn get_ipv4_ssh_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv4_ssh_service().await;
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_ssh_service(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv6_ssh_service().await;
    HttpResponse::Ok().json(list)
}

async fn add_ipv4_ssh_service(
    ip_addr: web::Json<SocketAddrV4>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv4_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_ssh_service(
    ip_addr: web::Json<SocketAddrV6>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv6_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_ssh_service(
    ip_addr: web::Json<SocketAddrV4>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv4_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_ssh_service(
    ip_addr: web::Json<SocketAddrV6>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv6_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// --- SSH whitelist handlers ---

async fn is_ssh_white_list_enable(service: web::Data<ProtocolFilter>) -> impl Responder {
    let enabled = service.is_ssh_white_list_enable().await;
    HttpResponse::Ok().json(enabled)
}

async fn enable_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    match service.enable_ssh_white_list().await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn disable_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    match service.disable_ssh_white_list().await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_ipv4_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv4_ssh_white_list().await;
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_ssh_white_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv6_ssh_white_list().await;
    HttpResponse::Ok().json(list)
}

async fn add_ipv4_ssh_white_list(
    ip_addr: web::Json<Ipv4Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv4_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_ssh_white_list(
    ip_addr: web::Json<Ipv6Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv6_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_ssh_white_list(
    ip_addr: web::Json<Ipv4Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv4_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_ssh_white_list(
    ip_addr: web::Json<Ipv6Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv6_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// --- SSH blacklist handlers ---

async fn get_ipv4_ssh_black_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv4_ssh_black_list().await;
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_ssh_black_list(service: web::Data<ProtocolFilter>) -> impl Responder {
    let list = service.get_ipv6_ssh_black_list().await;
    HttpResponse::Ok().json(list)
}

async fn add_ipv4_ssh_black_list(
    ip_addr: web::Json<Ipv4Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv4_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_ssh_black_list(
    ip_addr: web::Json<Ipv6Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.add_ipv6_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_ssh_black_list(
    ip_addr: web::Json<Ipv4Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv4_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_ssh_black_list(
    ip_addr: web::Json<Ipv6Addr>,
    service: web::Data<ProtocolFilter>,
) -> impl Responder {
    match service.remove_ipv6_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
