use crate::core::infrastructure::ml_alert::MLAlert;
use crate::web::websocket::alert_websocket;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/ml")
        .service(websocket_alert)
}

#[get("/websocket/alert")]
async fn websocket_alert(
    req: HttpRequest,
    stream: web::Payload,
    ai: web::Data<MLAlert>,
) -> impl Responder {
    match alert_websocket::websocket_alert(req, stream, ai).await {
        Ok(response) => response,
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("WebSocket error: {}", err))
        }
    }
}