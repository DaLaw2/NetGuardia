use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::{Message, MessageStream, Session, handle};
use futures_util::StreamExt;
use macros::log;
use tokio::sync::broadcast;

use crate::infrastructure::health::SystemHealth;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::health::SystemHealthMetrics;
use crate::model::log::http::HttpLog;

pub async fn websocket_system_health(
    req: HttpRequest,
    body: web::Payload,
    health: web::Data<SystemHealth>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;

    let broadcast_rx = health.subscribe_to_metrics();

    actix_web::rt::spawn(async move {
        handle_health_connection(session, msg_stream, broadcast_rx).await;
    });

    Ok(response)
}

async fn handle_health_connection(
    mut session: Session,
    mut msg_stream: MessageStream,
    mut broadcast_rx: broadcast::Receiver<SystemHealthMetrics>,
) {
    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            broadcast_result = broadcast_rx.recv() => {
                match broadcast_result {
                    Ok(metrics) => {
                        if !send_metrics(&mut session, &metrics).await {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log!(HttpLog::WebSocketLagged(skipped));
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            },
        }
    }

    let _ = session.close(None).await;
}

async fn handle_client_message(
    session: &mut Session,
    msg_result: Option<Result<Message, actix_ws::ProtocolError>>,
) -> bool {
    match msg_result {
        Some(Ok(Message::Text(_))) => true,
        Some(Ok(Message::Ping(bytes))) => session.pong(&bytes).await.is_ok(),
        Some(Ok(Message::Close(reason))) => {
            let _ = (session.clone()).close(reason).await;
            false
        }
        Some(Err(err)) => {
            log!(HttpError::WebSocketError(err));
            false
        }
        None => false,
        _ => true,
    }
}

async fn send_metrics(session: &mut Session, metrics: &SystemHealthMetrics) -> bool {
    match serde_json::to_string(metrics) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            false
        }
    }
}
