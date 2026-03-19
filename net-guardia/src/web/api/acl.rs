use std::net::{SocketAddrV4, SocketAddrV6};

use actix_web::{web, HttpResponse, Responder, Scope};

use crate::core::ebpf::access_control::AccessControl;
use crate::model::direction::FlowDirection;
use crate::model::list_type::ListType;

pub fn initialize() -> Scope {
    web::scope("/acl")
        .route("/ipv4/{direction}/{list_type}", web::get().to(get_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::get().to(get_ipv6_list))
        .route("/ipv4/{direction}/{list_type}", web::put().to(add_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::put().to(add_ipv6_list))
        .route("/ipv4/{direction}/{list_type}", web::delete().to(remove_ipv4_list))
        .route("/ipv6/{direction}/{list_type}", web::delete().to(remove_ipv6_list))
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

async fn add_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match access_control.add_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn add_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match access_control.add_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv4_list(
    address: web::Json<SocketAddrV4>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match access_control.remove_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_ipv6_list(
    address: web::Json<SocketAddrV6>,
    path: web::Path<(FlowDirection, ListType)>,
    access_control: web::Data<AccessControl>,
) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match access_control.remove_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
