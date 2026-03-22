use std::net::{SocketAddrV4, SocketAddrV6};

use actix_web::{web, HttpResponse, Responder, Scope};
use serde::Deserialize;

use crate::interface::port::repository::RepositoryPort;

type Repo = dyn RepositoryPort;
use crate::core::ebpf::access_control::AccessControl;
use crate::core::ebpf::geo_block::GeoBlock;
use crate::model::direction::FlowDirection;
use crate::model::list_type::ListType;

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

async fn get_ipv4_list(
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = access_control.get_ipv4_list(direction, list_type).await;
    HttpResponse::Ok().json(list)
}

async fn get_ipv6_list(
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = access_control.get_ipv6_list(direction, list_type).await;
    HttpResponse::Ok().json(list)
}

fn direction_str(d: FlowDirection) -> &'static str {
    match d { FlowDirection::Source => "source", FlowDirection::Destination => "destination" }
}

fn list_type_str(l: ListType) -> &'static str {
    match l { ListType::White => "whitelist", ListType::Black => "blacklist" }
}

async fn add_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
    db: web::Data<Repo>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    if let Err(e) = db.insert_acl_rule(4, direction_str(direction), list_type_str(list_type), &address.ip().to_string(), address.port()) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }
    match access_control.add_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
    db: web::Data<Repo>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    if let Err(e) = db.insert_acl_rule(6, direction_str(direction), list_type_str(list_type), &address.ip().to_string(), address.port()) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }
    match access_control.add_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
    db: web::Data<Repo>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    if let Err(e) = db.delete_acl_rule(4, direction_str(direction), list_type_str(list_type), &address.ip().to_string(), address.port()) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }
    match access_control.remove_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
    db: web::Data<Repo>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    if let Err(e) = db.delete_acl_rule(6, direction_str(direction), list_type_str(list_type), &address.ip().to_string(), address.port()) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }
    match access_control.remove_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_geo_blocked(
    geo_block: web::Data<GeoBlock>,
) -> impl Responder {
    let blocked = geo_block.get_blocked_countries();
    HttpResponse::Ok().json(serde_json::json!({"blocked_countries": blocked}))
}

async fn block_geo_countries(
    body: web::Json<CountryCodesRequest>,
    geo_block: web::Data<GeoBlock>,
    db: web::Data<Repo>,
) -> impl Responder {
    let codes = body.into_inner().country_codes;
    for code in &codes {
        if let Err(e) = db.insert_geo_country(code) {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    }
    match geo_block.block_countries(&codes) {
        Ok(total_prefixes) => HttpResponse::Ok().json(serde_json::json!({
            "blocked_countries": geo_block.get_blocked_countries(),
            "total_prefixes": total_prefixes,
        })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn unblock_geo_countries(
    body: web::Json<CountryCodesRequest>,
    geo_block: web::Data<GeoBlock>,
    db: web::Data<Repo>,
) -> impl Responder {
    let codes = body.into_inner().country_codes;
    for code in &codes {
        if let Err(e) = db.delete_geo_country(code) {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": e.to_string()}));
        }
    }
    match geo_block.unblock_countries(&codes) {
        Ok(total_prefixes) => HttpResponse::Ok().json(serde_json::json!({
            "blocked_countries": geo_block.get_blocked_countries(),
            "total_prefixes": total_prefixes,
        })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}
