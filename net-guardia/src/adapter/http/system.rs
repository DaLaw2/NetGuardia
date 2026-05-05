use actix_web::{HttpResponse, Responder, Scope, web};
use serde::Deserialize;

use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::domain::common::config::constants::{
    ENFORCE_MODE_ENFORCE, ENFORCE_MODE_ML_ONLY, ENFORCE_MODE_MONITOR, PERMISSION_SYSTEM_ADMIN,
};
use crate::infrastructure::logger::Logger;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::system::{ShutdownHandle, ShutdownMode};
use crate::utils::boot_time;

#[derive(Deserialize)]
struct EnforceModeRequest {
    mode: String,
}

pub fn initialize() -> Scope {
    web::scope("/system")
        .route("/boot-time", web::get().to(get_boot_time))
        .route("/enforce-mode", web::get().to(get_enforce_mode))
        .route("/enforce-mode", web::put().to(set_enforce_mode))
        .route("/xdp-mode", web::get().to(get_xdp_mode))
        .route("/config", web::get().to(get_config))
        .route("/config", web::put().to(update_config))
        .route("/log-level", web::get().to(get_log_level))
        .route("/log-level", web::put().to(set_log_level))
        .route("/shutdown", web::post().to(shutdown))
        .route("/restart", web::post().to(restart))
}

async fn get_boot_time() -> impl Responder {
    HttpResponse::Ok().json(boot_time::boot_time())
}

async fn get_enforce_mode(handler: web::Data<EnforceModeHandler>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"mode": handler.get_mode()}))
}

async fn set_enforce_mode(
    body: web::Json<EnforceModeRequest>,
    handler: web::Data<EnforceModeHandler>,
) -> impl Responder {
    let mode = &body.mode;
    if mode != ENFORCE_MODE_MONITOR && mode != ENFORCE_MODE_ML_ONLY && mode != ENFORCE_MODE_ENFORCE {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Mode must be 'monitor', 'ml_only', or 'enforce'"}));
    }

    match handler.change_mode(mode.clone()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"mode": mode})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_xdp_mode(runtime_state: web::Data<arc_swap::ArcSwap<RuntimeState>>) -> impl Responder {
    let xdp = runtime_state.load().xdp.clone();

    HttpResponse::Ok().json(serde_json::json!({
        "ingress_mode": xdp.ingress_mode,
        "egress_mode": xdp.egress_mode,
    }))
}

async fn get_config(svc: web::Data<ConfigService>) -> impl Responder {
    HttpResponse::Ok().json(svc.get_config().await)
}

async fn get_log_level(logging: web::Data<Logger>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "level": logging.current_level(),
    }))
}

#[derive(Deserialize)]
struct LogLevelRequest {
    level: String,
}

async fn set_log_level(body: web::Json<LogLevelRequest>, logging: web::Data<Logger>) -> impl Responder {
    match logging.set_level(&body.level) {
        Ok(new_level) => HttpResponse::Ok().json(serde_json::json!({
            "level": new_level,
            "message": "Log level updated",
        })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e})),
    }
}

/// HTTP config keys that require a server restart to take effect.
const HTTP_RELOAD_KEYS: &[&str] = &["http_port", "cors_allowed_origins", "force_https"];

async fn update_config(
    body: web::Json<serde_json::Value>,
    svc: web::Data<ConfigService>,
    handle: web::Data<ShutdownHandle>,
) -> impl Responder {
    match svc.update_config(&body).await {
        Ok(updated) => {
            let needs_restart = updated.iter().any(|k| HTTP_RELOAD_KEYS.contains(&k.as_str()));
            if needs_restart {
                // Auto-trigger restart for HTTP config changes
                let triggered = handle.trigger(ShutdownMode::Restart);
                HttpResponse::Ok().json(serde_json::json!({
                    "updated": updated,
                    "message": if triggered {
                        "Settings updated. Server restarting to apply HTTP config changes."
                    } else {
                        "Settings updated. Restart already in progress."
                    },
                    "restarting": triggered,
                }))
            } else {
                HttpResponse::Ok().json(serde_json::json!({
                    "updated": updated,
                    "message": if updated.is_empty() { "No changes" } else { "Settings updated" },
                }))
            }
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn shutdown(auth: AuthClaims, handle: web::Data<ShutdownHandle>) -> impl Responder {
    if !auth.permissions.iter().any(|p| p == PERMISSION_SYSTEM_ADMIN) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Requires system:admin permission"}));
    }
    if handle.trigger(ShutdownMode::Shutdown) {
        HttpResponse::Ok().json(serde_json::json!({"message": "Shutdown initiated"}))
    } else {
        HttpResponse::Conflict().json(serde_json::json!({"error": "Shutdown already in progress"}))
    }
}

async fn restart(auth: AuthClaims, handle: web::Data<ShutdownHandle>) -> impl Responder {
    if !auth.permissions.iter().any(|p| p == PERMISSION_SYSTEM_ADMIN) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Requires system:admin permission"}));
    }
    if handle.trigger(ShutdownMode::Restart) {
        HttpResponse::Ok().json(serde_json::json!({"message": "Restart initiated"}))
    } else {
        HttpResponse::Conflict().json(serde_json::json!({"error": "Shutdown already in progress"}))
    }
}
