use crate::core::ai::AI;
use crate::web::websocket::alert_websocket;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/ai")
        .service(websocket_alert)
}

#[get("/websocket/alert")]
async fn websocket_alert(req: HttpRequest, stream: web::Payload) -> impl Responder {
    match alert_websocket::websocket_alert(req, stream, ).await {
        Ok(response) => response,
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err))
        }
    }
}