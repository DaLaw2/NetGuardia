use crate::core::statistics::Statistics;
use crate::web::utils::flow_websocket::{IPv4FlowWebSocket, IPv6FlowWebSocket};
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
use actix_web_actors::ws::start;
use crate::model::direction::{Direction, FlowDirection};
use crate::model::time_type::TimeType;

pub fn initialize() -> Scope {
    web::scope("/statistics")
        .service(get_ipv4_flow)
        .service(get_ipv6_flow)
        .service(websocket_ipv4)
        .service(websocket_ipv6)
}

#[get("/get/ipv4/{direction}/{flow_direction}/{time_type}")]
async fn get_ipv4_flow(path: web::Path<(Direction, FlowDirection, TimeType)>) -> impl Responder {
    let (direction, flow_direction, time_type) = path.into_inner();
    let flow_data = Statistics::get_ipv4_flow_data(direction, flow_direction, time_type).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/get/ipv6/{direction}/{flow_direction}/{time_type}")]
async fn get_ipv6_flow(path: web::Path<(Direction, FlowDirection, TimeType)>) -> impl Responder {
    let (direction, flow_direction, time_type) = path.into_inner();
    let flow_data = Statistics::get_ipv6_flow_data(direction, flow_direction, time_type).await;
    HttpResponse::Ok().json(web::Json(flow_data))
}

#[get("/websocket/ipv4/{direction}/{flow_direction}/{time_type}")]
async fn websocket_ipv4(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
) -> Result<HttpResponse, Error> {
    let (direction, flow_direction, time_type) = path.into_inner();
    let websocket = IPv4FlowWebSocket {
        direction,
        flow_direction,
        time_type,
        interval: None,
    };
    start(websocket, &req, stream)
}

#[get("/websocket/ipv6/{direction}/{flow_direction}/{time_type}")]
async fn websocket_ipv6(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
) -> Result<HttpResponse, Error> {
    let (direction, flow_direction, time_type) = path.into_inner();
    let websocket = IPv6FlowWebSocket {
        direction,
        flow_direction,
        time_type,
        interval: None,
    };
    start(websocket, &req, stream)
}
