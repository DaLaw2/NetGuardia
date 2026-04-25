use actix_web::rt::spawn;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::handle;

use super::ws_bridge;
use crate::infrastructure::health::SystemHealth;

pub async fn websocket_system_health(
    req: HttpRequest,
    body: web::Payload,
    health: web::Data<SystemHealth>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;
    let rx = health.subscribe_to_metrics();
    spawn(ws_bridge::broadcast_json(session, msg_stream, rx));
    Ok(response)
}
