use crate::model::alert::Alert;
use tokio::sync::broadcast;
use futures_util::StreamExt;
use tokio::time::{interval, Duration};
use actix_ws::{handle, Message, Session};
use actix_web::{web, HttpRequest, HttpResponse, Result};
use tracing::{error, warn};

pub async fn websocket_alert(
    req: HttpRequest, 
    body: web::Payload,
    broadcast_rx: broadcast::Receiver<Alert>,
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
    mut broadcast_rx: broadcast::Receiver<Alert>,
) {
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            alert_result = broadcast_rx.recv() => {
                if !handle_broadcast_message(&mut session, alert_result).await {
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
                "ping" => {
                    session.text("pong").await.is_ok()
                },
                _ => {
                    let error_msg = serde_json::json!({
                        "available_commands": ["ping"]
                    });
                    match serde_json::to_string(&error_msg) {
                        Ok(error_json) => session.text(error_json).await.is_ok(),
                        Err(_) => true 
                    }
                }
            }
        },
        Some(Ok(Message::Ping(bytes))) => {
            session.pong(&bytes).await.is_ok()
        },
        Some(Ok(Message::Close(reason))) => {
            let _ = (session.clone()).close(reason).await;
            false
        },
        Some(Err(err)) => {
            error!("WebSocket error: {}", err);
            false
        },
        None => {
            false
        },
        _ => {
            true 
        }
    }
}

async fn handle_broadcast_message(
    session: &mut Session,
    alert_result: Result<Alert, broadcast::error::RecvError>,
) -> bool {
    match alert_result {
        Ok(alert) => {
            let message = serde_json::json!(alert);
            match serde_json::to_string(&message) {
                Ok(json) => session.text(json).await.is_ok(),
                Err(err) => {
                    error!("Failed to serialize alert: {}", err);
                    true
                }
            }
        },
        Err(broadcast::error::RecvError::Lagged(skipped)) => {
            warn!("Alert WebSocket lagged, skipped {} messages", skipped);
            let lag_msg = serde_json::json!({
                "message": format!("Connection lagged, skipped {} messages", skipped)
            });
            match serde_json::to_string(&lag_msg) {
                Ok(json) => session.text(json).await.is_ok(),
                Err(_) => true
            }
        },
        Err(broadcast::error::RecvError::Closed) => {
            let close_msg = serde_json::json!({
                "message": "Alert monitoring stopped"
            });
            if let Ok(json) = serde_json::to_string(&close_msg) {
                let _ = session.text(json).await;
            }
            false
        }
    }
}
