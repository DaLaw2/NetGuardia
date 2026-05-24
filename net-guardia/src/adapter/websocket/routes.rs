use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Responder, Scope, web};
use tokio::sync::broadcast;

use super::{alert_websocket, drop_websocket, flow_websocket, fusion_websocket, health_websocket};
use crate::adapter::ebpf::drop_monitor::DropMonitor;
use crate::adapter::http::helpers::{internal_error, json_error};
use crate::adapter::http::session::SessionCookieService;
use crate::core::common::statistics::FlowStatistics;
use crate::core::identity::session_service::SessionService;
use crate::core::inference::alert::MLAlert;
use crate::domain::common::config::constants::{
    PERMISSION_AI_DETECTION_READ, PERMISSION_DASHBOARD_READ, PERMISSION_DROPS_READ, PERMISSION_FUSION_READ,
    PERMISSION_TRAFFIC_MAP_READ,
};
use crate::domain::common::event::ThreatDetectedEvent;
use crate::domain::identity::auth::Claims;
use crate::interface::system::health_query::HealthQuery;

pub fn initialize() -> Scope {
    web::scope("/ws")
        .route("/health", web::get().to(health_ws))
        .route("/alerts", web::get().to(alerts_ws))
        .route("/fusion", web::get().to(fusion_ws))
        .route("/flows", web::get().to(flows_ws))
        .route("/drops", web::get().to(drops_ws))
}

fn validate_ws_auth(
    req: &HttpRequest,
    session_service: &web::Data<SessionService>,
    cookie_service: &web::Data<SessionCookieService>,
    required_permission: &str,
) -> Result<(), HttpResponse> {
    let Some(cookie) = req.cookie(cookie_service.cookie_name()) else {
        return Err(json_error(StatusCode::UNAUTHORIZED, "Missing authentication cookie"));
    };
    let claims = session_service
        .claims_for_session(cookie.value())
        .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "Invalid or expired session"))?;
    if has_permission(&claims, required_permission) {
        Ok(())
    } else {
        Err(json_error(StatusCode::FORBIDDEN, "Insufficient permissions"))
    }
}

fn has_permission(claims: &Claims, required_permission: &str) -> bool {
    claims.permissions.iter().any(|p| p == required_permission)
}

async fn health_ws(
    req: HttpRequest,
    stream: web::Payload,
    health: web::Data<dyn HealthQuery>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_auth(&req, &session_service, &cookie_service, PERMISSION_DASHBOARD_READ) {
        return resp;
    }
    health_websocket::websocket_system_health(req, stream, health)
        .await
        .unwrap_or_else(|err| internal_error(format!("WebSocket error: {}", err)))
}

async fn alerts_ws(
    req: HttpRequest,
    stream: web::Payload,
    ai: web::Data<MLAlert>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_auth(&req, &session_service, &cookie_service, PERMISSION_AI_DETECTION_READ) {
        return resp;
    }
    alert_websocket::websocket_alert(req, stream, ai)
        .await
        .unwrap_or_else(|err| internal_error(format!("WebSocket error: {}", err)))
}

async fn fusion_ws(
    req: HttpRequest,
    stream: web::Payload,
    threat_tx: web::Data<broadcast::Sender<ThreatDetectedEvent>>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_auth(&req, &session_service, &cookie_service, PERMISSION_FUSION_READ) {
        return resp;
    }
    fusion_websocket::websocket_fusion(req, stream, threat_tx)
        .await
        .unwrap_or_else(|err| internal_error(format!("WebSocket error: {}", err)))
}

async fn flows_ws(
    req: HttpRequest,
    stream: web::Payload,
    stats: web::Data<FlowStatistics>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_auth(&req, &session_service, &cookie_service, PERMISSION_TRAFFIC_MAP_READ) {
        return resp;
    }
    match flow_websocket::flow_stats_ws(req, stream, stats).await {
        Ok(response) => response,
        Err(err) => internal_error(format!("WebSocket error: {}", err)),
    }
}

async fn drops_ws(
    req: HttpRequest,
    stream: web::Payload,
    monitor: web::Data<DropMonitor>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_auth(&req, &session_service, &cookie_service, PERMISSION_DROPS_READ) {
        return resp;
    }
    drop_websocket::websocket_drops(req, stream, monitor)
        .await
        .unwrap_or_else(|err| internal_error(format!("WebSocket error: {}", err)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims_with_permissions(permissions: &[&str]) -> Claims {
        Claims {
            sub: 1,
            username: "operator".to_string(),
            role: "viewer".to_string(),
            permissions: permissions.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    #[test]
    fn ws_permissions_match_http_read_resources() {
        let claims = claims_with_permissions(&[
            PERMISSION_DASHBOARD_READ,
            PERMISSION_AI_DETECTION_READ,
            PERMISSION_FUSION_READ,
            PERMISSION_TRAFFIC_MAP_READ,
            PERMISSION_DROPS_READ,
        ]);

        for required in [
            PERMISSION_DASHBOARD_READ,
            PERMISSION_AI_DETECTION_READ,
            PERMISSION_FUSION_READ,
            PERMISSION_TRAFFIC_MAP_READ,
            PERMISSION_DROPS_READ,
        ] {
            assert!(has_permission(&claims, required));
        }
    }

    #[test]
    fn missing_ws_permission_is_detectable() {
        let claims = claims_with_permissions(&[PERMISSION_DASHBOARD_READ]);

        assert!(!has_permission(&claims, PERMISSION_TRAFFIC_MAP_READ));
    }
}
