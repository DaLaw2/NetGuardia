use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_ws::{handle, Message, Session};
use futures_util::StreamExt;
use macros::log;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};

use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::healthy::SystemHealthMetrics;
use crate::model::log::http::HttpLog;

pub async fn websocket_system_health(
    req: HttpRequest,
    body: web::Payload,
    broadcast_rx: broadcast::Receiver<SystemHealthMetrics>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;

    actix_web::rt::spawn(async move {
        handle_websocket_connection(session, msg_stream, broadcast_rx).await;
    });

    Ok(response)
}

async fn handle_websocket_connection(
    mut session: Session,
    mut msg_stream: actix_ws::MessageStream,
    mut broadcast_rx: broadcast::Receiver<SystemHealthMetrics>,
) {
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            metrics_result = broadcast_rx.recv() => {
                if !handle_broadcast_message(&mut session, metrics_result).await {
                    break;
                }
            },
            _ = ping_interval.tick() => {
                if session.ping(b"heartbeat").await.is_err() {
                    break;
                }
            }
        }
    }

    let _ = session.close(None).await;
}

async fn handle_client_message(
    session: &mut Session,
    msg_result: Option<Result<Message, actix_ws::ProtocolError>>,
) -> bool {
    match msg_result {
        Some(Ok(Message::Text(text))) => {
            let text = text.trim();
            match text {
                "ping" => session.text("pong").await.is_ok(),
                "get_current" => {
                    let current_metrics = crate::core::health::SystemHealth::get_current_metrics().await;
                    match serde_json::to_string(&current_metrics) {
                        Ok(json) => session.text(json).await.is_ok(),
                        Err(err) => {
                            log!(MiscError::SerializeError(err));
                            true
                        }
                    }
                }
                _ => {
                    let error_msg = serde_json::json!({
                        "available_commands": ["ping", "get_current"]
                    });
                    match serde_json::to_string(&error_msg) {
                        Ok(error_json) => session.text(error_json).await.is_ok(),
                        Err(_) => true,
                    }
                }
            }
        }
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

async fn handle_broadcast_message(
    session: &mut Session,
    metrics_result: Result<SystemHealthMetrics, broadcast::error::RecvError>,
) -> bool {
    match metrics_result {
        Ok(metrics) => {
            let message = serde_json::json!(metrics);
            match serde_json::to_string(&message) {
                Ok(json) => session.text(json).await.is_ok(),
                Err(err) => {
                    log!(MiscError::SerializeError(err));
                    true
                }
            }
        }
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            log!(HttpLog::WebSocketLaged(skipped));
            let lag_msg = serde_json::json!({
                "message": format!("Connection lagged, skipped {} messages", skipped)
            });
            match serde_json::to_string(&lag_msg) {
                Ok(json) => session.text(json).await.is_ok(),
                Err(_) => true,
            }
        }
        Err(broadcast::error::RecvError::Closed) => {
            let close_msg = serde_json::json!({
                "message": "Health monitoring stopped"
            });
            if let Ok(json) = serde_json::to_string(&close_msg) {
                let _ = session.text(json).await;
            }
            false
        }
    }
}
