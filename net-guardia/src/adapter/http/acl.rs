use std::net::{SocketAddrV4, SocketAddrV6};

use actix_web::{HttpResponse, Responder, Scope, web};
use serde::Deserialize;

use crate::core::acl_service::AclService;
use crate::model::access_control::list_type::ListType;
use crate::model::monitoring::direction::FlowDirection;

#[derive(Deserialize)]
struct CountryCodesRequest {
    country_codes: Vec<String>,
}

pub fn initialize() -> Scope {
    web::scope("/acl")
        .route("/ipv4/{direction}/{list_type}", web::get().to(get_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::get().to(get_ipv6_list))
        .route("/ipv4/{direction}/{list_type}", web::put().to(add_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::put().to(add_ipv6_list))
        .route("/ipv4/{direction}/{list_type}", web::delete().to(remove_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::delete().to(remove_ipv6_list))
        .route("/geo/blocked", web::get().to(get_geo_blocked))
        .route("/geo/block", web::put().to(block_geo_countries))
        .route("/geo/unblock", web::delete().to(unblock_geo_countries))
}

async fn get_ipv4_list(path: web::Path<(FlowDirection, ListType)>, acl: web::Data<AclService>) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = acl.access_control().get_ipv4_list(direction, list_type);
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_list(path: web::Path<(FlowDirection, ListType)>, acl: web::Data<AclService>) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = acl.access_control().get_ipv6_list(direction, list_type);
    HttpResponse::Ok().json(list)
}

async fn add_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    acl: web::Data<AclService>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    match acl.add_ipv4(direction, list_type, address.into_inner()) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    acl: web::Data<AclService>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    match acl.add_ipv6(direction, list_type, address.into_inner()) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    acl: web::Data<AclService>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    match acl.remove_ipv4(direction, list_type, address.into_inner()) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    acl: web::Data<AclService>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    match acl.remove_ipv6(direction, list_type, address.into_inner()) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_geo_blocked(acl: web::Data<AclService>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"blocked_countries": acl.get_blocked_countries()}))
}

async fn block_geo_countries(body: web::Json<CountryCodesRequest>, acl: web::Data<AclService>) -> impl Responder {
    let codes = body.into_inner().country_codes;
    match acl.block_geo_countries(&codes) {
        Ok(total_prefixes) => HttpResponse::Ok().json(serde_json::json!({
            "blocked_countries": acl.get_blocked_countries(),
            "total_prefixes": total_prefixes,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn unblock_geo_countries(body: web::Json<CountryCodesRequest>, acl: web::Data<AclService>) -> impl Responder {
    let codes = body.into_inner().country_codes;
    match acl.unblock_geo_countries(&codes) {
        Ok(total_prefixes) => HttpResponse::Ok().json(serde_json::json!({
            "blocked_countries": acl.get_blocked_countries(),
            "total_prefixes": total_prefixes,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
