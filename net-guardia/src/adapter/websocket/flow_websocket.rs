use std::time::Duration;

use actix_web::{HttpRequest, HttpResponse, web};
use actix_ws::Message;
use futures_util::StreamExt;
use tokio::time::interval;

use crate::infrastructure::statistics::FlowStatistics;
use crate::model::flow_stats::FlowSubscription;

/// Default subscription: all flows, no filter, 5 second interval
fn default_subscription() -> FlowSubscription {
    FlowSubscription {
        direction: None,
        window_secs: None,
        top_n: None,
        interval_secs: Some(5),
    }
}

/// Push { summary, flows } payload to the client.
fn push_payload(stats: &FlowStatistics, sub: &FlowSubscription) -> Option<String> {
    let payload = stats.get_flow_payload(sub);
    serde_json::to_string(&payload).ok()
}

pub async fn flow_stats_ws(
    req: HttpRequest,
    body: web::Payload,
    stats: web::Data<FlowStatistics>,
) -> Result<HttpResponse, actix_web::Error> {
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, body)?;

    actix_web::rt::spawn(async move {
        let mut subscription = default_subscription();
        let mut ticker = interval(Duration::from_secs(subscription.interval_secs.unwrap_or(5)));

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Some(json) = push_payload(&stats, &subscription)
                        && session.text(json).await.is_err() {
                            break;
                    }
                }
                msg = msg_stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<FlowSubscription>(&text) {
                                Ok(new_sub) => {
                                    let new_interval = new_sub.interval_secs.unwrap_or(5).max(1);
                                    subscription = new_sub;
                                    subscription.interval_secs = Some(new_interval);
                                    ticker = interval(Duration::from_secs(new_interval));

                                    if let Some(json) = push_payload(&stats, &subscription)
                                        && session.text(json).await.is_err() {
                                            break;
                                    }
                                }
                                Err(e) => {
                                    let err_msg = serde_json::json!({"error": format!("Invalid subscription: {}", e)});
                                    if session.text(err_msg.to_string()).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
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
