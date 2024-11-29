use crate::core::monitor::Monitor;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
use crate::web::utils::map_util::{transform_ipv4_flow_data, transform_ipv6_flow_data};

pub fn initialize() -> Scope {
    web::scope("/monitor")
        .service(get_src_ipv4_1min)
        .service(get_src_ipv4_10min)
        .service(get_src_ipv4_1hour)
        .service(get_src_ipv6_1min)
        .service(get_src_ipv6_10min)
        .service(get_src_ipv6_1hour)
        .service(get_dst_ipv4_1min)
        .service(get_dst_ipv4_10min)
        .service(get_dst_ipv4_1hour)
        .service(get_dst_ipv6_1min)
        .service(get_dst_ipv6_10min)
        .service(get_dst_ipv6_1hour)
}

#[get("/get/src/ipv4/1min")]
async fn get_src_ipv4_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::SrcIPv4_1Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/src/ipv4/10min")]
async fn get_src_ipv4_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::SrcIPv4_10Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/src/ipv4/1hour")]
async fn get_src_ipv4_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::SrcIPv4_1Hour).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/src/ipv6/1min")]
async fn get_src_ipv6_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_1Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/src/ipv6/10min")]
async fn get_src_ipv6_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_10Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/src/ipv6/1hour")]
async fn get_src_ipv6_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_1Hour).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv4/1min")]
async fn get_dst_ipv4_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::DstIPv4_1Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv4/10min")]
async fn get_dst_ipv4_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::DstIPv4_10Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv4/1hour")]
async fn get_dst_ipv4_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::DstIPv4_1Hour).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv6/1min")]
async fn get_dst_ipv6_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_1Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv6/10min")]
async fn get_dst_ipv6_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_10Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/dst/ipv6/1hour")]
async fn get_dst_ipv6_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::SrcIPv6_1Hour).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/websocket")]
async fn websocket(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Forbidden().finish())
}
