use crate::core::control::Control;
use crate::model::http_method::HttpMethod;
use actix_web::{delete, get, post, put, web, HttpResponse, Responder, Scope};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

pub fn initialize() -> Scope {
    web::scope("/control")
        .service(get_ipv4_src_black_list)
        .service(get_ipv6_src_black_list)
        .service(add_ipv4_src_black_list)
        .service(add_ipv6_src_black_list)
        .service(remove_ipv4_src_black_list)
        .service(remove_ipv6_src_black_list)
        .service(get_ipv4_dst_black_list)
        .service(get_ipv6_dst_black_list)
        .service(add_ipv4_dst_black_list)
        .service(add_ipv6_dst_black_list)
        .service(remove_ipv4_dst_black_list)
        .service(remove_ipv6_dst_black_list)
        .service(get_ipv4_http_service)
        .service(get_ipv6_http_service)
        .service(add_ipv4_http_service)
        .service(add_ipv6_http_service)
        .service(remove_ipv4_http_service)
        .service(remove_ipv6_http_service)
        .service(is_ssh_white_list_enable)
        .service(enable_ssh_white_list)
        .service(disable_ssh_white_list)
        .service(get_ipv4_ssh_service)
        .service(get_ipv6_ssh_service)
        .service(add_ipv4_ssh_service)
        .service(add_ipv6_ssh_service)
        .service(remove_ipv4_ssh_service)
        .service(remove_ipv6_ssh_service)
        .service(get_ipv4_ssh_white_list)
        .service(get_ipv6_ssh_white_list)
        .service(add_ipv4_ssh_white_list)
        .service(add_ipv6_ssh_white_list)
        .service(remove_ipv4_ssh_white_list)
        .service(remove_ipv6_ssh_white_list)
        .service(get_ipv4_ssh_black_list)
        .service(get_ipv6_ssh_black_list)
        .service(add_ipv4_ssh_black_list)
        .service(add_ipv6_ssh_black_list)
        .service(remove_ipv4_ssh_black_list)
        .service(remove_ipv6_ssh_black_list)
        .service(get_ipv4_scanner_list)
        .service(get_ipv6_scanner_list)
        .service(remove_ipv4_scanner_list)
        .service(remove_ipv6_scanner_list)
}

#[get("/ipv4/src_black_list")]
async fn get_ipv4_src_black_list() -> impl Responder {
    let list = Control::get_ipv4_src_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/src_black_list")]
async fn get_ipv6_src_black_list() -> impl Responder {
    let list = Control::get_ipv6_src_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/src_black_list")]
async fn add_ipv4_src_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::add_ipv4_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/src_black_list")]
async fn add_ipv6_src_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::add_ipv6_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/src_black_list")]
async fn remove_ipv4_src_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::remove_ipv4_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/src_black_list")]
async fn remove_ipv6_src_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::remove_ipv6_src_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/dst_black_list")]
async fn get_ipv4_dst_black_list() -> impl Responder {
    let list = Control::get_ipv4_dst_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/dst_black_list")]
async fn get_ipv6_dst_black_list() -> impl Responder {
    let list = Control::get_ipv6_dst_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/dst_black_list")]
async fn add_ipv4_dst_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::add_ipv4_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/dst_black_list")]
async fn add_ipv6_dst_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::add_ipv6_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/dst_black_list")]
async fn remove_ipv4_dst_black_list(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::remove_ipv4_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/dst_black_list")]
async fn remove_ipv6_dst_black_list(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::remove_ipv6_dst_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/http_service")]
async fn get_ipv4_http_service() -> impl Responder {
    let list = Control::get_ipv4_http_service().await;
    HttpResponse::Ok().json(web::Json(list))
}

// Problem
#[get("/ipv6/http_service")]
async fn get_ipv6_http_service() -> impl Responder {
    let list = Control::get_ipv6_http_service().await;
    HttpResponse::Ok().json(web::Json(list))
}

// Problem
#[put("/ipv4/http_service")]
async fn add_ipv4_http_service(
    payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match Control::add_ipv4_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Problem
#[put("/ipv6/http_service")]
async fn add_ipv6_http_service(
    payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match Control::add_ipv6_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Problem
#[delete("/ipv4/http_service")]
async fn remove_ipv4_http_service(
    payload: web::Json<(SocketAddrV4, Vec<HttpMethod>)>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match Control::remove_ipv4_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// Problem
#[delete("/ipv6/http_service")]
async fn remove_ipv6_http_service(
    payload: web::Json<(SocketAddrV6, Vec<HttpMethod>)>,
) -> impl Responder {
    let (addr, methods) = payload.into_inner();
    match Control::remove_ipv6_http_service(addr, methods).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ssh_white_list")]
async fn is_ssh_white_list_enable() -> impl Responder {
    let enabled = Control::is_ssh_white_list_enable().await;
    HttpResponse::Ok().json(enabled)
}

#[post("/ssh_white_list/enable")]
async fn enable_ssh_white_list() -> impl Responder {
    match Control::enable_ssh_white_list().await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/ssh_white_list/disable")]
async fn disable_ssh_white_list() -> impl Responder {
    match Control::disable_ssh_white_list().await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/ssh_service")]
async fn get_ipv4_ssh_service() -> impl Responder {
    let list = Control::get_ipv4_ssh_service().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/ssh_service")]
async fn get_ipv6_ssh_service() -> impl Responder {
    let list = Control::get_ipv6_ssh_service().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/ssh_service")]
async fn add_ipv4_ssh_service(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::add_ipv4_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/ssh_service")]
async fn add_ipv6_ssh_service(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::add_ipv6_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/ssh_service")]
async fn remove_ipv4_ssh_service(ip_addr: web::Json<SocketAddrV4>) -> impl Responder {
    match Control::remove_ipv4_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/ssh_service")]
async fn remove_ipv6_ssh_service(ip_addr: web::Json<SocketAddrV6>) -> impl Responder {
    match Control::remove_ipv6_ssh_service(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/ssh_white_list")]
async fn get_ipv4_ssh_white_list() -> impl Responder {
    let list = Control::get_ipv4_ssh_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/ssh_white_list")]
async fn get_ipv6_ssh_white_list() -> impl Responder {
    let list = Control::get_ipv6_ssh_white_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/ssh_white_list")]
async fn add_ipv4_ssh_white_list(ip_addr: web::Json<Ipv4Addr>) -> impl Responder {
    match Control::add_ipv4_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/ssh_white_list")]
async fn add_ipv6_ssh_white_list(ip_addr: web::Json<Ipv6Addr>) -> impl Responder {
    match Control::add_ipv6_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/ssh_white_list")]
async fn remove_ipv4_ssh_white_list(ip_addr: web::Json<Ipv4Addr>) -> impl Responder {
    match Control::remove_ipv4_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/ssh_white_list")]
async fn remove_ipv6_ssh_white_list(ip_addr: web::Json<Ipv6Addr>) -> impl Responder {
    match Control::remove_ipv6_ssh_white_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/ssh_black_list")]
async fn get_ipv4_ssh_black_list() -> impl Responder {
    let list = Control::get_ipv4_ssh_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/ssh_black_list")]
async fn get_ipv6_ssh_black_list() -> impl Responder {
    let list = Control::get_ipv6_ssh_black_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[put("/ipv4/ssh_black_list")]
async fn add_ipv4_ssh_black_list(ip_addr: web::Json<Ipv4Addr>) -> impl Responder {
    match Control::add_ipv4_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/ipv6/ssh_black_list")]
async fn add_ipv6_ssh_black_list(ip_addr: web::Json<Ipv6Addr>) -> impl Responder {
    match Control::add_ipv6_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv4/ssh_black_list")]
async fn remove_ipv4_ssh_black_list(ip_addr: web::Json<Ipv4Addr>) -> impl Responder {
    match Control::remove_ipv4_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/ssh_black_list")]
async fn remove_ipv6_ssh_black_list(ip_addr: web::Json<Ipv6Addr>) -> impl Responder {
    match Control::remove_ipv6_ssh_black_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/ipv4/scanner_list")]
async fn get_ipv4_scanner_list() -> impl Responder {
    let list = Control::get_ipv4_scanner_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[get("/ipv6/scanner_list")]
async fn get_ipv6_scanner_list() -> impl Responder {
    let list = Control::get_ipv6_scanner_list().await;
    HttpResponse::Ok().json(web::Json(list))
}

#[delete("/ipv4/scanner_list")]
async fn remove_ipv4_scanner_list(ip_addr: web::Json<Ipv4Addr>) -> impl Responder {
    match Control::remove_ipv4_scanner_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/ipv6/scanner_list")]
async fn remove_ipv6_scanner_list(ip_addr: web::Json<Ipv6Addr>) -> impl Responder {
    match Control::remove_ipv6_scanner_list(ip_addr.into_inner()).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}
