use crate::core::statistics::Statistics;
use crate::model::flow_type::FlowType;
use crate::web::utils::flow_websocket::{IPv4FlowWebSocket, IPv6FlowWebSocket};
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_actors::ws::start;

pub fn initialize() -> Scope {
    web::scope("/statistics")
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
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Src1Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv4/src/10min")]
async fn get_ipv4_src_10min() -> impl Responder {
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Src10Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv4/src/1hour")]
async fn get_ipv4_src_1hour() -> impl Responder {
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Src1Hour).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/src/1min")]
async fn get_ipv6_src_1min() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src1Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/src/10min")]
async fn get_ipv6_src_10min() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src10Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/src/1hour")]
async fn get_ipv6_src_1hour() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src1Hour).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv4/dst/1min")]
async fn get_ipv4_dst_1min() -> impl Responder {
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Dst1Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv4/dst/10min")]
async fn get_ipv4_dst_10min() -> impl Responder {
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Dst10Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv4/dst/1hour")]
async fn get_ipv4_dst_1hour() -> impl Responder {
    let flow_data = Statistics::get_ipv4_flow_data(FlowType::Dst1Hour).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/dst/1min")]
async fn get_ipv6_dst_1min() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src1Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/dst/10min")]
async fn get_ipv6_dst_10min() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src10Min).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/dst/1hour")]
async fn get_ipv6_dst_1hour() -> impl Responder {
    let flow_data = Statistics::get_ipv6_flow_data(FlowType::Src1Hour).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/websocket/ipv4/{flow_type}")]
async fn websocket_ipv4(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<FlowType>,
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
    path: web::Path<FlowType>,
) -> Result<HttpResponse, Error> {
    let flow_type = path.into_inner();
    let websocket = IPv6FlowWebSocket {
        flow_type,
        interval: None,
    };
    start(websocket, &req, stream)
}
