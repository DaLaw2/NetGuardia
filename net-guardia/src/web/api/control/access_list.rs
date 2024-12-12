use crate::core::control::access_list::AccessList;
use crate::model::direction::Direction;
use crate::model::list_type::ListType;
use actix_web::{delete, get, put, web, HttpResponse, Responder, Scope};
use std::net::{SocketAddrV4, SocketAddrV6};

pub fn initialize() -> Scope {
    web::scope("/access_list")
        .service(get_ipv4_list)
        .service(get_ipv6_list)
        .service(add_ipv4_list)
        .service(add_ipv6_list)
        .service(remove_ipv4_list)
        .service(remove_ipv6_list)
}

#[get("/ipv4/{direction}/{list_type}")]
async fn get_ipv4_list(path: web::Path<(Direction, ListType)>) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = AccessList::get_ipv4_list(direction, list_type).await;
    HttpResponse::Ok().json(list)
}

#[get("/ipv6/{direction}/{list_type}")]
async fn get_ipv6_list(path: web::Path<(Direction, ListType)>) -> impl Responder {
    let (direction, list_type) = path.into_inner();
    let list = AccessList::get_ipv6_list(direction, list_type).await;
    HttpResponse::Ok().json(list)
}

#[put("/ipv4/{direction}/{list_type}")]
async fn add_ipv4_list(address: web::Json<SocketAddrV4>, path: web::Path<(Direction, ListType)>) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match AccessList::add_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/{direction}/{list_type}")]
async fn add_ipv6_list(address: web::Json<SocketAddrV6>, path: web::Path<(Direction, ListType)>) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match AccessList::add_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/{direction}/{list_type}")]
async fn remove_ipv4_list(address: web::Json<SocketAddrV4>, path: web::Path<(Direction, ListType)>) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match AccessList::remove_ipv4_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/{direction}/{list_type}")]
async fn remove_ipv6_list(address: web::Json<SocketAddrV6>, path: web::Path<(Direction, ListType)>) -> impl Responder {
    let address = address.into_inner();
    let (direction, list_type) = path.into_inner();
    match AccessList::remove_ipv6_list(direction, list_type, address).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
