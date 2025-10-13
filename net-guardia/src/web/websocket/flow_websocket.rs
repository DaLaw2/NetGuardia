use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse, Result};
use actix_ws::{handle, Message, MessageStream, Session};
use futures_util::StreamExt;
use macros::log;
use tokio::time::{interval, Duration};

use crate::core::ebpf::statistics::Statistics;
use crate::core::infrastructure::app_config::AppConfig;
use crate::model::direction::{Direction, FlowDirection};
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::time_type::TimeType;

pub async fn websocket_ipv4_flow(
    req: HttpRequest,
    body: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
    app_config: web::Data<AppConfig>,
    statistics: web::Data<Statistics>,
) -> Result<HttpResponse> {
    let app_config = app_config.into_inner();
    let statistics = statistics.into_inner();
    let (direction, flow_direction, time_type) = path.into_inner();
    let (response, session, msg_stream) = handle(&req, body)?;

    actix_web::rt::spawn(async move {
        handle_ipv4_flow_connection(
            app_config,
            statistics,
            session,
            msg_stream,
            direction,
            flow_direction,
            time_type,
        )
        .await;
    });

    Ok(response)
}

pub async fn websocket_ipv6_flow(
    req: HttpRequest,
    body: web::Payload,
    path: web::Path<(Direction, FlowDirection, TimeType)>,
    app_config: web::Data<AppConfig>,
    statistics: web::Data<Statistics>,
) -> Result<HttpResponse> {
    let app_config = app_config.into_inner();
    let statistics = statistics.into_inner();
    let (direction, flow_direction, time_type) = path.into_inner();
    let (response, session, msg_stream) = handle(&req, body)?;

    actix_web::rt::spawn(async move {
        handle_ipv6_flow_connection(
            app_config,
            statistics,
            session,
            msg_stream,
            direction,
            flow_direction,
            time_type,
        )
        .await;
    });

    Ok(response)
}

async fn handle_ipv4_flow_connection(
    app_config: Arc<AppConfig>,
    statistics: Arc<Statistics>,
    mut session: Session,
    mut msg_stream: MessageStream,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) {
    let config = app_config.config.clone();
    let refresh_interval = Duration::from_secs(config.refresh_interval);
    let mut data_interval = interval(refresh_interval);

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            _ = data_interval.tick() => {
                if !send_ipv4_flow_data(&statistics, &mut session, direction, flow_direction, time_type).await {
                    break;
                }
            },
        }
    }

    let _ = session.close(None).await;
}

async fn handle_ipv6_flow_connection(
    app_config: Arc<AppConfig>,
    statistics: Arc<Statistics>,
    mut session: Session,
    mut msg_stream: MessageStream,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) {
    let config = app_config.config.clone();
    let refresh_interval = Duration::from_secs(config.refresh_interval);
    let mut data_interval = interval(refresh_interval);

    loop {
        tokio::select! {
            msg_result = msg_stream.next() => {
                if !handle_client_message(&mut session, msg_result).await {
                    break;
                }
            },
            _ = data_interval.tick() => {
                if !send_ipv6_flow_data(&statistics, &mut session, direction, flow_direction, time_type).await {
                    break;
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

async fn send_ipv4_flow_data(
    statistics: &Arc<Statistics>,
    session: &mut Session,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) -> bool {
    let flow_data = statistics
        .get_ipv4_flow_data(direction, flow_direction, time_type)
        .await;
    match serde_json::to_string(&flow_data) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            true
        }
    }
}

async fn send_ipv6_flow_data(
    statistics: &Arc<Statistics>,
    session: &mut Session,
    direction: Direction,
    flow_direction: FlowDirection,
    time_type: TimeType,
) -> bool {
    let flow_data = statistics
        .get_ipv6_flow_data(direction, flow_direction, time_type)
        .await;
    match serde_json::to_string(&flow_data) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            true
        }
    }
}
