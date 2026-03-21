use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_ws::{handle, Message, MessageStream, Session};
use futures_util::StreamExt;
use macros::log;
use tokio::sync::broadcast;

use crate::core::ebpf::drop_monitor::{DropMonitor, DropEventMessage};
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::log::http::HttpLog;

pub async fn websocket_drops(
    req: HttpRequest,
    body: web::Payload,
    monitor: web::Data<DropMonitor>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;

    let broadcast_rx = monitor.subscribe();

    actix_web::rt::spawn(async move {
        handle_drop_connection(session, msg_stream, broadcast_rx).await;
    });

    Ok(response)
}

async fn handle_drop_connection(
    mut session: Session,
    mut msg_stream: MessageStream,
    mut broadcast_rx: broadcast::Receiver<DropEventMessage>,
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
                    Ok(event) => {
                        if !send_drop_event(&mut session, &event).await {
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

async fn send_drop_event(session: &mut Session, event: &DropEventMessage) -> bool {
    match serde_json::to_string(event) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            false
        }
    }
}
