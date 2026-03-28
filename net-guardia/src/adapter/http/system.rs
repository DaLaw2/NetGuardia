use actix_web::{web, HttpResponse, Responder, Scope};
use serde::Deserialize;

use crate::core::config_service::ConfigService;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::interface::communication::command_types::ChangeEnforceModeCommand;
use crate::interface::communication::query_types::GetEnforceModeQuery;
use crate::interface::port::repository::RepositoryPort;

type Repo = dyn RepositoryPort;

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
}

async fn get_boot_time() -> impl Responder {
    HttpResponse::Ok().json(crate::utils::boot_time::boot_time())
}

async fn get_enforce_mode(comm: web::Data<CommunicationManager>) -> impl Responder {
    match comm.send_query(GetEnforceModeQuery).await {
        Ok(mode) => HttpResponse::Ok().json(serde_json::json!({"mode": mode})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn set_enforce_mode(
    body: web::Json<EnforceModeRequest>,
    comm: web::Data<CommunicationManager>,
) -> impl Responder {
    let mode = &body.mode;
    if mode != "monitor" && mode != "enforce" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Mode must be 'monitor' or 'enforce'"}));
    }

    match comm.send_command(ChangeEnforceModeCommand { mode: mode.clone() }).await {
        Ok(_) => {
            HttpResponse::Ok().json(serde_json::json!({"mode": mode}))
        }
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_xdp_mode(db: web::Data<Repo>) -> impl Responder {
    let ingress = db.get_setting("xdp_ingress_mode")
        .ok().flatten().unwrap_or_else(|| "unknown".to_string());
    let egress = db.get_setting("xdp_egress_mode")
        .ok().flatten().unwrap_or_else(|| "unknown".to_string());

    HttpResponse::Ok().json(serde_json::json!({
        "ingress_mode": ingress,
        "egress_mode": egress,
    }))
}

async fn get_config(svc: web::Data<ConfigService>) -> impl Responder {
    HttpResponse::Ok().json(svc.get_config())
}

async fn update_config(
    body: web::Json<serde_json::Value>,
    svc: web::Data<ConfigService>,
) -> impl Responder {
    match svc.update_config(&body) {
        Ok(updated) => {
            HttpResponse::Ok().json(serde_json::json!({
                "updated": updated,
                "message": if updated.is_empty() { "No changes" } else { "Settings updated. Restart required for changes to take effect." }
            }))
        }
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({"error": e.to_string()})),
    }
}
