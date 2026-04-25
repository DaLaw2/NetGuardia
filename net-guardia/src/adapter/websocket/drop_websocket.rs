use actix_web::rt::spawn;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::handle;

use super::ws_bridge;
use crate::adapter::ebpf::drop_monitor::DropMonitor;

pub async fn websocket_drops(
    req: HttpRequest,
    body: web::Payload,
    monitor: web::Data<DropMonitor>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;
    let rx = monitor.subscribe();
    spawn(ws_bridge::broadcast_json(session, msg_stream, rx));
    Ok(response)
}
