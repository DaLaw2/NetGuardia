use actix_ws::{Message, MessageStream, Session};
use futures_util::StreamExt;
use macros::log;
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::common::error::codec::CodecError;
use crate::common::error::http::HttpError;
use crate::common::log::http::HttpLog;

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

pub fn serialize_json<T: Serialize>(value: &T) -> Option<String> {
    match serde_json::to_string(value) {
        Ok(json) => Some(json),
        Err(err) => {
            log!(CodecError::SerializeFailed(err));
            None
        }
    }
}

pub async fn broadcast_json<T: Serialize + Clone + Send + 'static>(
    session: Session,
    msg_stream: MessageStream,
    rx: broadcast::Receiver<T>,
) {
    broadcast_loop(session, msg_stream, rx, |event| serialize_json(event)).await;
}

pub async fn broadcast_loop<T: Clone + Send + 'static>(
    mut session: Session,
    mut msg_stream: MessageStream,
    mut rx: broadcast::Receiver<T>,
    to_json: impl Fn(&T) -> Option<String>,
) {
    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            broadcast_result = rx.recv() => {
                match broadcast_result {
                    Ok(event) => {
                        let Some(json) = to_json(&event) else {
                            continue;
                        };
                        if session.text(json).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        log!(HttpLog::WebSocketLagged(skipped));
                        continue;
                    }
                    Err(RecvError::Closed) => {
                        break;
                    }
                }
            },
        }
    }

    let _ = session.close(None).await;
}
