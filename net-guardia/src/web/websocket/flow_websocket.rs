use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::Message;
use futures_util::StreamExt;
use tokio::time::interval;

use crate::core::infrastructure::statistics::FlowStatistics;

pub async fn flow_stats_ws(
    req: HttpRequest,
    body: web::Payload,
    stats: web::Data<FlowStatistics>,
) -> Result<HttpResponse, actix_web::Error> {
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    actix_web::rt::spawn(async move {
        let mut ticker = interval(Duration::from_secs(5));
        let mut rx = stats.subscribe();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    stats.broadcast();
                }
                result = rx.recv() => {
                    match result {
                        Ok(flows) => {
                            if let Ok(json) = serde_json::to_string(&flows) {
                                if session.text(json).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                msg = msg_stream.next() => {
                    match msg {
                        Some(Ok(Message::Ping(bytes))) => {
                            if session.pong(&bytes).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }
    });

    Ok(response)
}
