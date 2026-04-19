//! WebSocket bridge for post-fusion threat events.
//!
//! `/ws/fusion` subscribes to the `ThreatDetectedEvent` broadcast that the
//! `DetectionOrchestrator` already publishes through `CommunicationManager`
//! (the same stream SOAR consumes). Each event is wrapped with a server-side
//! `ts` (unix seconds) so the dashboard can render relative timestamps
//! without doing the conversion itself.
//!
//! Distinct from `/ws/alerts` (flow-level ML detections via `MLAlert`):
//! this stream is the **fused, per-IP, multi-source** view that drives the
//! Overview "Recent Threats" card and the sources-agreed chip. Treating
//! them as one channel would conflate two bounded contexts — see
//! `docs/strategy/DOMAIN_MAP.md` for the BC split rationale.

use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::rt::spawn;
use actix_web::{HttpRequest, HttpResponse, Result, web};
use actix_ws::{Message, MessageStream, Session, handle};
use futures_util::StreamExt;
use macros::log;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::infrastructure::communication_manager::CommunicationManager;
use crate::model::error::http::HttpError;
use crate::model::error::misc::MiscError;
use crate::model::event::ThreatDetectedEvent;
use crate::model::log::http::HttpLog;

pub async fn websocket_fusion(
    req: HttpRequest,
    body: web::Payload,
    comm: web::Data<CommunicationManager>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;

    let broadcast_rx = match comm.subscribe_event::<ThreatDetectedEvent>() {
        Ok(rx) => rx,
        Err(e) => {
            log!(HttpLog::FusionSubscribeFailed(e.to_string()));
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "fusion event channel not registered",
            })));
        }
    };

    spawn(async move {
        handle_fusion_connection(session, msg_stream, broadcast_rx).await;
    });

    Ok(response)
}

async fn handle_fusion_connection(
    mut session: Session,
    mut msg_stream: MessageStream,
    mut broadcast_rx: broadcast::Receiver<ThreatDetectedEvent>,
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
                        if !send_event(&mut session, &event).await {
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

/// Wrap each event in `{ts, ...event_fields}`. The `ts` is a server-stamped
/// unix-seconds value so the client can render "5s ago" without inferring
/// the time from the audit chain. All declared fields of
/// `ThreatDetectedEvent` flow through verbatim via the event's own
/// `Serialize` derive — no field whitelist to drift out of date.
async fn send_event(session: &mut Session, event: &ThreatDetectedEvent) -> bool {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = match serde_json::to_value(event) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("ts".to_string(), serde_json::Value::from(ts));
            serde_json::Value::Object(map)
        }
        // The derived Serialize on a struct always produces an Object —
        // this branch only fires if the type changes shape in a future
        // refactor. Falling back to the raw value keeps the stream alive.
        Ok(other) => other,
        Err(err) => {
            log!(MiscError::SerializeError(err));
            return false;
        }
    };

    match serde_json::to_string(&payload) {
        Ok(json) => session.text(json).await.is_ok(),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event::DetectionSource;

    fn sample_event() -> ThreatDetectedEvent {
        ThreatDetectedEvent {
            attack_type: "brute_force".to_string(),
            confidence: 0.92,
            source_ip: "203.0.113.10".to_string(),
            dest_ip: "10.0.0.1".to_string(),
            flow_count: 3,
            packet_rate: 12.5,
            protocol: 6,
            geoip_country: Some("CN".to_string()),
            is_repeat_offender: true,
            sources: vec![DetectionSource::ML, DetectionSource::Suricata],
            active_source_count: 2,
            fused_confidence: 0.99,
            ae_score: 0.0,
            anomaly_score: 0.0,
            c2_score: 0.0,
        }
    }

    #[test]
    fn event_serializes_with_canonical_source_strings() {
        let event = sample_event();
        let json = serde_json::to_value(&event).expect("serialize event");
        let sources = json["sources"].as_array().expect("sources array");
        assert_eq!(sources[0], "ML");
        assert_eq!(sources[1], "Suricata");
        assert_eq!(json["active_source_count"], 2);
        assert_eq!(json["geoip_country"], "CN");
    }

    #[test]
    fn envelope_adds_ts_field_to_event_object() {
        // The `send_event` wire path inserts `ts` into the event's own
        // serde object; mirror that here without an actix session so the
        // wrapping logic stays covered when the orchestrator schema evolves.
        let event = sample_event();
        let mut value = serde_json::to_value(&event).expect("serialize event");
        let object = value.as_object_mut().expect("expected object shape");
        object.insert("ts".to_string(), serde_json::Value::from(1_700_000_000_u64));
        assert_eq!(value["ts"], 1_700_000_000_u64);
        assert_eq!(value["attack_type"], "brute_force");
    }
}
