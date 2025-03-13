use crate::core::ai::AI;
use crate::web::utils::alert_websocket::AlertWebSocket;
use actix_web::{get, web, HttpRequest, Responder, Scope};
use actix_web_actors::ws::start;

pub fn initialize() -> Scope {
    web::scope("/ai")
        .service(websocket_alert)
}

#[get("/websocket/alert")]
async fn websocket_alert(req: HttpRequest, stream: web::Payload) -> impl Responder {
    let broadcast_rx = AI::subscribe().await;
    let websocket = AlertWebSocket {
        handle: None,
        broadcast_rx,
    };
    start(websocket, &req, stream)
}
