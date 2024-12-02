use crate::core::monitor::Monitor;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use crate::web::utils::map_util::{transform_ipv4_flow_data, transform_ipv6_flow_data};
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_actors::ws::start;
use tracing::info;
use crate::web::utils::flow_websocket::{IPv4FlowWebSocket, IPv6FlowWebSocket};

pub fn initialize() -> Scope {
    web::scope("/monitor")
        .service(get_ipv4_src_1min)
        .service(get_ipv4_src_10min)
        .service(get_ipv4_src_1hour)
        .service(get_ipv6_src_1min)
        .service(get_ipv6_src_10min)
        .service(get_ipv6_src_1hour)
        .service(get_ipv4_dst_1min)
        .service(get_ipv4_dst_10min)
        .service(get_ipv4_dst_1hour)
        .service(get_ipv6_dst_1min)
        .service(get_ipv6_dst_10min)
        .service(get_ipv6_dst_1hour)
        .service(websocket_ipv4)
        .service(websocket_ipv6)
}

#[get("/get/ipv4/src/1min")]
async fn get_ipv4_src_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Src1Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv4/src/10min")]
async fn get_ipv4_src_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Src10Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv4/src/1hour")]
async fn get_ipv4_src_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Src1Hour).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/src/1min")]
async fn get_ipv6_src_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src1Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/src/10min")]
async fn get_ipv6_src_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src10Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/src/1hour")]
async fn get_ipv6_src_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src1Hour).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv4/dst/1min")]
async fn get_ipv4_dst_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Dst1Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv4/dst/10min")]
async fn get_ipv4_dst_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Dst10Min).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv4/dst/1hour")]
async fn get_ipv4_dst_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv4_flow_data(IPv4FlowType::Dst1Hour).await;
    let formated = transform_ipv4_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/dst/1min")]
async fn get_ipv6_dst_1min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src1Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/dst/10min")]
async fn get_ipv6_dst_10min() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src10Min).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/get/ipv6/dst/1hour")]
async fn get_ipv6_dst_1hour() -> impl Responder {
    let flow_data = Monitor::get_ipv6_flow_data(IPv6FlowType::Src1Hour).await;
    let formated = transform_ipv6_flow_data(flow_data);
    HttpResponse::Ok().json(web::Json(formated))
}

#[get("/websocket/ipv4/{flow_type}")]
async fn websocket_ipv4(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<IPv4FlowType>,
) -> Result<HttpResponse, Error> {
    let flow_type = path.into_inner();
    let websocket = IPv4FlowWebSocket {
        flow_type,
        interval: None,
    };
    start(websocket, &req, stream)
}

#[get("/websocket/ipv6/{flow_type}")]
async fn websocket_ipv6(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<IPv6FlowType>,
) -> Result<HttpResponse, Error> {
    let flow_type = path.into_inner();
    let websocket = IPv6FlowWebSocket {
        flow_type,
        interval: None,
    };
    start(websocket, &req, stream)
}
