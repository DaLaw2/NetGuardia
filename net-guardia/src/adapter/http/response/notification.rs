use actix_web::{HttpResponse, Scope, web};
use serde::Deserialize;

use crate::adapter::http::helpers::{ok_json_or_error, ok_or_error};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::common::notification_service::NotificationService;

pub fn initialize() -> Scope {
    web::scope("/notifications")
        .route("/telegram/config", web::get().to(get_telegram_config))
        .route("/telegram/config", web::post().to(set_telegram_config))
        .route("/telegram/test", web::post().to(test_telegram))
        .route("/smtp/test", web::post().to(test_smtp))
}

async fn get_telegram_config(_auth: AuthClaims, svc: web::Data<NotificationService>) -> HttpResponse {
    ok_json_or_error(svc.get_telegram_config().await)
}

#[derive(Deserialize)]
struct TelegramConfigRequest {
    bot_token: String,
    chat_id: String,
}

async fn set_telegram_config(
    _auth: AuthClaims,
    svc: web::Data<NotificationService>,
    body: web::Json<TelegramConfigRequest>,
) -> HttpResponse {
    ok_or_error(svc.set_telegram_config(&body.bot_token, &body.chat_id).await)
}

async fn test_telegram(_auth: AuthClaims, svc: web::Data<NotificationService>) -> HttpResponse {
    match svc.test_telegram().await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"success": true, "message": "Test message sent"})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}

async fn test_smtp(_auth: AuthClaims, svc: web::Data<NotificationService>) -> HttpResponse {
    match svc.test_smtp().await {
        Ok(msg) => HttpResponse::Ok().json(serde_json::json!({"success": true, "message": msg})),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}
