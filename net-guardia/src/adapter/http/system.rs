use actix_web::{HttpResponse, Responder, Scope, web};
use serde::Deserialize;

use crate::adapter::http::helpers::{bad_request, conflict, forbidden, internal_error};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::domain::common::config::constants::PERMISSION_SYSTEM_ADMIN;
use crate::domain::common::config::system::EnforceMode;
use crate::interface::system::system_control::{BootTimeQuery, LogLevelControl, SystemCommandPort, XdpModeQuery};

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

async fn get_boot_time(boot_time: web::Data<dyn BootTimeQuery>) -> impl Responder {
    HttpResponse::Ok().json(boot_time.boot_time_ns())
}

async fn get_enforce_mode(handler: web::Data<EnforceModeHandler>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"mode": handler.get_mode().to_string()}))
}

async fn set_enforce_mode(
    body: web::Json<EnforceModeRequest>,
    handler: web::Data<EnforceModeHandler>,
) -> impl Responder {
    let Ok(mode) = body.mode.parse::<EnforceMode>() else {
        return bad_request("Mode must be 'monitor', 'ml_only', or 'enforce'");
    };

    match handler.change_mode(mode).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"mode": mode.to_string()})),
        Err(e) => internal_error(e),
    }
}

async fn get_xdp_mode(runtime_state: web::Data<dyn XdpModeQuery>) -> impl Responder {
    let xdp = runtime_state.get_xdp_modes();

    HttpResponse::Ok().json(serde_json::json!({
        "ingress_mode": xdp.ingress_mode,
        "egress_mode": xdp.egress_mode,
    }))
}

async fn get_config(svc: web::Data<ConfigService>) -> impl Responder {
    HttpResponse::Ok().json(svc.get_config().await)
}

async fn get_log_level(logging: web::Data<dyn LogLevelControl>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "level": logging.current_level(),
    }))
}

#[derive(Deserialize)]
struct LogLevelRequest {
    level: String,
}

async fn set_log_level(body: web::Json<LogLevelRequest>, logging: web::Data<dyn LogLevelControl>) -> impl Responder {
    match logging.set_level(&body.level) {
        Ok(new_level) => HttpResponse::Ok().json(serde_json::json!({
            "level": new_level,
            "message": "Log level updated",
        })),
        Err(e) => bad_request(e),
    }
}

const HTTP_RELOAD_KEYS: &[&str] = &["http_port", "cors_allowed_origins", "force_https"];

fn updated_keys_need_http_restart(updated: &[String]) -> bool {
    updated.iter().any(|key| HTTP_RELOAD_KEYS.contains(&key.as_str()))
}

async fn update_config(
    body: web::Json<serde_json::Value>,
    svc: web::Data<ConfigService>,
    handle: web::Data<dyn SystemCommandPort>,
) -> impl Responder {
    match svc.update_config(&body).await {
        Ok(updated) => {
            if updated_keys_need_http_restart(&updated) {
                let triggered = handle.trigger_restart();
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
        Err(e) => bad_request(e),
    }
}

async fn shutdown(auth: AuthClaims, handle: web::Data<dyn SystemCommandPort>) -> impl Responder {
    if !auth.permissions.iter().any(|p| p == PERMISSION_SYSTEM_ADMIN) {
        return forbidden("Requires system:admin permission");
    }
    if handle.trigger_shutdown() {
        HttpResponse::Ok().json(serde_json::json!({"message": "Shutdown initiated"}))
    } else {
        conflict("Shutdown already in progress")
    }
}

async fn restart(auth: AuthClaims, handle: web::Data<dyn SystemCommandPort>) -> impl Responder {
    if !auth.permissions.iter().any(|p| p == PERMISSION_SYSTEM_ADMIN) {
        return forbidden("Requires system:admin permission");
    }
    if handle.trigger_restart() {
        HttpResponse::Ok().json(serde_json::json!({"message": "Restart initiated"}))
    } else {
        conflict("Shutdown already in progress")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expiry_update_does_not_require_http_restart() {
        assert!(!updated_keys_need_http_restart(&["session_expiry_hours".to_string()]));
    }

    #[test]
    fn non_http_runtime_update_does_not_require_http_restart() {
        assert!(!updated_keys_need_http_restart(&[
            "smtp_host".to_string(),
            "beaconing_cv_threshold".to_string()
        ]));
    }
}
