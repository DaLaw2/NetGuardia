use actix_web::{web, HttpResponse, Responder, Scope};
use serde::Deserialize;

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
    let scope = web::scope("/system")
        .route("/boot-time", web::get().to(get_boot_time))
        .route("/enforce-mode", web::get().to(get_enforce_mode))
        .route("/enforce-mode", web::put().to(set_enforce_mode))
        .route("/xdp-mode", web::get().to(get_xdp_mode));

    #[cfg(feature = "license")]
    let scope = scope.route("/license", web::get().to(get_license_info));

    scope
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

#[cfg(feature = "license")]
async fn get_license_info(license_info: web::Data<crate::core::license::LicenseInfo>) -> impl Responder {
    HttpResponse::Ok().json(license_info.get_ref())
}
