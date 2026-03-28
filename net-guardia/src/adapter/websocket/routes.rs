use actix_web::{web, HttpRequest, HttpResponse, Responder, Scope};
use serde::Deserialize;

use crate::core::auth::jwt::JwtService;
use crate::core::ebpf::drop_monitor::DropMonitor;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::statistics::FlowStatistics;
use crate::core::ml::alert::MLAlert;
use super::{alert_websocket, drop_websocket, flow_websocket, health_websocket};

#[derive(Deserialize)]
struct WsQuery {
    token: Option<String>,
}

pub fn initialize() -> Scope {
    web::scope("/ws")
        .route("/health", web::get().to(health_ws))
        .route("/alerts", web::get().to(alerts_ws))
        .route("/flows", web::get().to(flows_ws))
        .route("/drops", web::get().to(drops_ws))
}

fn validate_ws_token(
    req: &HttpRequest,
    query: &web::Query<WsQuery>,
    jwt: &web::Data<JwtService>,
) -> Result<(), HttpResponse> {
    // Prefer Authorization header over query parameter
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
        .or_else(|| query.token.clone());

    match token {
        Some(ref t) => jwt
            .validate_token(t)
            .map(|_| ())
            .map_err(|_| {
                HttpResponse::Unauthorized()
                    .json(serde_json::json!({"error": "Invalid or expired token"}))
            }),
        None => Err(HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Missing authentication: provide Authorization header or token query parameter"}))),
    }
}

async fn health_ws(
    req: HttpRequest,
    stream: web::Payload,
    health: web::Data<SystemHealth>,
    query: web::Query<WsQuery>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_token(&req, &query, &jwt) {
        return resp;
    }
    match health_websocket::websocket_system_health(req, stream, health).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}

async fn alerts_ws(
    req: HttpRequest,
    stream: web::Payload,
    ai: web::Data<MLAlert>,
    query: web::Query<WsQuery>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_token(&req, &query, &jwt) {
        return resp;
    }
    match alert_websocket::websocket_alert(req, stream, ai).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}

async fn flows_ws(
    req: HttpRequest,
    stream: web::Payload,
    stats: web::Data<FlowStatistics>,
    query: web::Query<WsQuery>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_token(&req, &query, &jwt) {
        return resp;
    }
    match flow_websocket::flow_stats_ws(req, stream, stats).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}

async fn drops_ws(
    req: HttpRequest,
    stream: web::Payload,
    monitor: web::Data<DropMonitor>,
    query: web::Query<WsQuery>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    if let Err(resp) = validate_ws_token(&req, &query, &jwt) {
        return resp;
    }
    match drop_websocket::websocket_drops(req, stream, monitor).await {
        Ok(response) => response,
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("WebSocket error: {}", err)})),
    }
}
