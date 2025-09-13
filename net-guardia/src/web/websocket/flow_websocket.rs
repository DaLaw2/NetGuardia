use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_ws::{handle, Message, MessageStream, Session};
use futures_util::StreamExt;
use macros::log;
use tokio::time::{interval, Duration};

use crate::core::app_config::AppConfig;
use crate::core::statistics::Statistics;
use crate::model::direction::{Direction, FlowDirection};
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::time_type::TimeType;

pub async fn websocket_ipv4_flow(
    req: HttpRequest,
    body: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
) -> Result<HttpResponse> {
    let (direction, flow_direction, time_type) = path.into_inner();
    let (response, session, msg_stream) = handle(&req, body)?;

    actix_web::rt::spawn(async move {
        handle_ipv4_flow_connection(session, msg_stream, direction, flow_direction, time_type).await;
    });

    Ok(response)
}

pub async fn websocket_ipv6_flow(
    req: HttpRequest,
    body: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
) -> Result<HttpResponse> {
    let (direction, flow_direction, time_type) = path.into_inner();
    let (response, session, msg_stream) = handle(&req, body)?;

    actix_web::rt::spawn(async move {
        handle_ipv6_flow_connection(session, msg_stream, direction, flow_direction, time_type).await;
    });

    Ok(response)
}

async fn handle_ipv4_flow_connection(
    mut session: Session,
    mut msg_stream: MessageStream,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) {
    let config = AppConfig::now_blocking();
    let refresh_interval = Duration::from_secs(config.refresh_interval);
    let mut data_interval = interval(refresh_interval);
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            _ = data_interval.tick() => {
                if !send_ipv4_flow_data(&mut session, direction, flow_direction, time_type).await {
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

async fn handle_ipv6_flow_connection(
    mut session: Session,
    mut msg_stream: MessageStream,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) {
    let config = AppConfig::now_blocking();
    let refresh_interval = Duration::from_secs(config.refresh_interval);
    let mut data_interval = interval(refresh_interval);
    let mut ping_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            _ = data_interval.tick() => {
                if !send_ipv6_flow_data(&mut session, direction, flow_direction, time_type).await {
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
                _ => {
                    let error_msg = serde_json::json!({
                        "available_commands": ["ping"]
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

async fn send_ipv4_flow_data(
    session: &mut Session,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) -> bool {
    let flow_data = Statistics::get_ipv4_flow_data(direction, flow_direction, time_type).await;
    match serde_json::to_string(&flow_data) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            true
        }
    }
}

async fn send_ipv6_flow_data(
    session: &mut Session,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) -> bool {
    let flow_data = Statistics::get_ipv6_flow_data(direction, flow_direction, time_type).await;
    match serde_json::to_string(&flow_data) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            true
        }
    }
}
