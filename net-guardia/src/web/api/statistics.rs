use crate::core::statistics::Statistics;
use crate::web::utils::flow_websocket;
use actix_web::{get, web, Error, HttpRequest, HttpResponse, Responder, Scope};
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
) -> impl Responder {

    match flow_websocket::websocket_ipv4_flow(req, stream, path).await {
        Ok(response) => response,
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err))
        }
    }
}

#[get("/websocket/ipv6/{direction}/{flow_direction}/{time_type}")]
async fn websocket_ipv6(
    req: HttpRequest,
    stream: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
) -> impl Responder {

    match flow_websocket::websocket_ipv6_flow(req, stream, path).await {
        Ok(response) => response,
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err))
        }
    }
}
