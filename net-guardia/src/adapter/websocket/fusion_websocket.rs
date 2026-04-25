//! WebSocket bridge for post-fusion threat events.
//!
//! `/ws/fusion` subscribes to the `ThreatDetectedEvent` broadcast channel
//! that the `DetectionOrchestrator` publishes to (the same stream SOAR
//! consumes). Each event is wrapped with a server-side
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
use actix_ws::handle;
use macros::log;
use tokio::sync::broadcast;

use super::ws_bridge;
use crate::domain::common::error::misc::MiscError;
use crate::domain::common::event::ThreatDetectedEvent;

pub async fn websocket_fusion(
    req: HttpRequest,
    body: web::Payload,
    threat_tx: web::Data<broadcast::Sender<ThreatDetectedEvent>>,
) -> Result<HttpResponse> {
    let (response, session, msg_stream) = handle(&req, body)?;
    let rx = threat_tx.subscribe();
    spawn(ws_bridge::broadcast_loop(session, msg_stream, rx, envelope_with_ts));
    Ok(response)
}

fn envelope_with_ts(event: &ThreatDetectedEvent) -> Option<String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let payload = match serde_json::to_value(event) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("ts".to_string(), serde_json::Value::from(ts));
            serde_json::Value::Object(map)
        }
        Ok(other) => other,
        Err(err) => {
            log!(MiscError::SerializeError(err));
            return None;
        }
    };

    match serde_json::to_string(&payload) {
        Ok(json) => Some(json),
        Err(err) => {
            log!(MiscError::SerializeError(err));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::common::event::DetectionSource;

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
        let json = envelope_with_ts(&sample_event()).expect("should serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert!(value["ts"].is_u64());
        assert_eq!(value["attack_type"], "brute_force");
    }
}
