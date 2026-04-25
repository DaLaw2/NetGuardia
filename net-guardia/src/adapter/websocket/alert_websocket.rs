use actix_web::rt::spawn;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::handle;

use crate::adapter::websocket::ws_bridge;
use crate::core::inference::alert::MLAlert;

pub async fn websocket_alert(req: HttpRequest, body: web::Payload, ai: web::Data<MLAlert>) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;
    let rx = ai.subscribe_to_alerts();
    spawn(ws_bridge::broadcast_json(session, msg_stream, rx));
    Ok(response)
}
