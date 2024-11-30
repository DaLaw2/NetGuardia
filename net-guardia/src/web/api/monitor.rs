use crate::core::monitor::Monitor;
use crate::model::flow_type::{IPv4FlowType, IPv6FlowType};
use crate::web::utils::map_util::{transform_ipv4_flow_data, transform_ipv6_flow_data};
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_actors::ws::start;
use tracing::info;
use crate::web::utils::flow_websocket::{IPv4FlowWebSocket, IPv6FlowWebSocket};

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
        .service(websocket_ipv4)
        .service(websocket_ipv6)
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

#[get("/websocket/ipv4/{flow_type}")]
async fn websocket_ipv4(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<IPv4FlowType>,
) -> Result<HttpResponse, Error> {
    info!("Try to connect ipv4 websocket");
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
