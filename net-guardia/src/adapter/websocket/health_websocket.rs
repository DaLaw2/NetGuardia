use std::sync::Arc;

use actix_web::rt::spawn;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::handle;

use super::ws_bridge;
use crate::domain::common::system::health::SystemHealthMetrics;
use crate::interface::system::health_query::HealthQuery;

pub async fn websocket_system_health(
    req: HttpRequest,
    body: web::Payload,
    health: web::Data<dyn HealthQuery>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;
    let rx = health.subscribe_to_metrics();
    spawn(ws_bridge::broadcast_loop(
        session,
        msg_stream,
        rx,
        |event: &Arc<SystemHealthMetrics>| ws_bridge::serialize_json(event.as_ref()),
    ));
    Ok(response)
}
