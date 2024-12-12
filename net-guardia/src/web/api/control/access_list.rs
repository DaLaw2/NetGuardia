use crate::core::control::access_list::AccessList;
use actix_web::{delete, get, put, web, HttpResponse, Responder, Scope};
use std::net::{SocketAddrV4, SocketAddrV6};

pub fn initialize() -> Scope {
    web::scope("/access_list")
        .service(get_ipv4_src_white_list)
        .service(get_ipv6_src_white_list)
        .service(add_ipv4_src_white_list)
        .service(add_ipv6_src_white_list)
        .service(remove_ipv4_src_white_list)
        .service(remove_ipv6_src_white_list)
        .service(get_ipv4_src_black_list)
        .service(get_ipv6_src_black_list)
        .service(add_ipv4_src_black_list)
        .service(add_ipv6_src_black_list)
        .service(remove_ipv4_src_black_list)
        .service(remove_ipv6_src_black_list)
}

#[get("/ipv4/src_white_list")]
async fn get_ipv4_src_white_list() -> impl Responder {
    let list = AccessList::get_ipv4_src_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/src_white_list")]
async fn get_ipv6_src_white_list() -> impl Responder {
    let list = AccessList::get_ipv6_src_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/src_white_list")]
async fn add_ipv4_src_white_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::add_ipv4_src_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/src_white_list")]
async fn add_ipv6_src_white_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::add_ipv6_src_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/src_white_list")]
async fn remove_ipv4_src_white_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::remove_ipv4_src_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/src_white_list")]
async fn remove_ipv6_src_white_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::remove_ipv6_src_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/dst_white_list")]
async fn get_ipv4_dst_white_list() -> impl Responder {
    let list = AccessList::get_ipv4_dst_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/dst_white_list")]
async fn get_ipv6_dst_white_list() -> impl Responder {
    let list = AccessList::get_ipv6_dst_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/dst_white_list")]
async fn add_ipv4_dst_white_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::add_ipv4_dst_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/dst_white_list")]
async fn add_ipv6_dst_white_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::add_ipv6_dst_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/dst_white_list")]
async fn remove_ipv4_dst_white_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::remove_ipv4_dst_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/dst_white_list")]
async fn remove_ipv6_dst_white_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::remove_ipv6_dst_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/src_black_list")]
async fn get_ipv4_src_black_list() -> impl Responder {
    let list = AccessList::get_ipv4_src_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/src_black_list")]
async fn get_ipv6_src_black_list() -> impl Responder {
    let list = AccessList::get_ipv6_src_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/src_black_list")]
async fn add_ipv4_src_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::add_ipv4_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/src_black_list")]
async fn add_ipv6_src_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::add_ipv6_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/src_black_list")]
async fn remove_ipv4_src_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::remove_ipv4_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/src_black_list")]
async fn remove_ipv6_src_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::remove_ipv6_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/dst_black_list")]
async fn get_ipv4_dst_black_list() -> impl Responder {
    let list = AccessList::get_ipv4_dst_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/dst_black_list")]
async fn get_ipv6_dst_black_list() -> impl Responder {
    let list = AccessList::get_ipv6_dst_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/dst_black_list")]
async fn add_ipv4_dst_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::add_ipv4_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/dst_black_list")]
async fn add_ipv6_dst_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::add_ipv6_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/dst_black_list")]
async fn remove_ipv4_dst_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match AccessList::remove_ipv4_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/dst_black_list")]
async fn remove_ipv6_dst_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match AccessList::remove_ipv6_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
