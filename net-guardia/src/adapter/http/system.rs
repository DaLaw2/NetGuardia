use actix_web::{HttpResponse, Responder, Scope, web};
use serde::Deserialize;

use crate::core::auth::extractor::AuthClaims;
use crate::core::config_service::ConfigService;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::system::{ShutdownHandle, ShutdownMode};
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::app_repo::AppRepo;
use crate::utils::boot_time;
use crate::utils::logging::Logging;

type Repo = dyn AppRepo;

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

async fn get_enforce_mode(comm: web::Data<CommunicationManager>) -> impl Responder {
    match comm.send_query(GetEnforceModeQuery).await {
        Ok(mode) => HttpResponse::Ok().json(serde_json::json!({"mode": mode})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn set_enforce_mode(
    body: web::Json<EnforceModeRequest>,
    comm: web::Data<CommunicationManager>,
) -> impl Responder {
    let mode = &body.mode;
    if mode != "monitor" && mode != "ml_only" && mode != "enforce" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Mode must be 'monitor', 'ml_only', or 'enforce'"}));
    }

    match comm.send_command(ChangeEnforceModeCommand { mode: mode.clone() }).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"mode": mode})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_xdp_mode(db: web::Data<Repo>) -> impl Responder {
    let ingress = db
        .get_setting("xdp_ingress_mode")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());
    let egress = db
        .get_setting("xdp_egress_mode")
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());

    HttpResponse::Ok().json(serde_json::json!({
        "ingress_mode": ingress,
        "egress_mode": egress,
    }))
}

async fn get_config(svc: web::Data<ConfigService>) -> impl Responder {
    HttpResponse::Ok().json(svc.get_config())
}

async fn get_log_level() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "level": Logging::current_level(),
    }))
}

#[derive(Deserialize)]
struct LogLevelRequest {
    level: String,
}

async fn set_log_level(body: web::Json<LogLevelRequest>) -> impl Responder {
    match Logging::set_level(&body.level) {
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
    match svc.update_config(&body) {
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
    if !auth.permissions.iter().any(|p| p == "system:admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Requires system:admin permission"}));
    }
    if handle.trigger(ShutdownMode::Shutdown) {
        HttpResponse::Ok().json(serde_json::json!({"message": "Shutdown initiated"}))
    } else {
        HttpResponse::Conflict().json(serde_json::json!({"error": "Shutdown already in progress"}))
    }
}

async fn restart(auth: AuthClaims, handle: web::Data<ShutdownHandle>) -> impl Responder {
    if !auth.permissions.iter().any(|p| p == "system:admin") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Requires system:admin permission"}));
    }
    if handle.trigger(ShutdownMode::Restart) {
        HttpResponse::Ok().json(serde_json::json!({"message": "Restart initiated"}))
    } else {
        HttpResponse::Conflict().json(serde_json::json!({"error": "Shutdown already in progress"}))
    }
}
