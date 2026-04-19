use actix_web::{HttpResponse, Responder, Scope, web};

use crate::core::auth::extractor::AuthClaims;
use crate::core::ml::adapter::ModelSourceState;
use crate::core::ml::engine::Engine;
use crate::core::ml::inference::Inference;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::model::event::AuditEvent;

/// Permission required to forcibly revert the active ML source to dormant.
/// Mirrors the upload handler's gate so swap-out and revert are symmetric:
/// without this, anyone holding `ai_detection:write` could disable the
/// detector silently while the upload path required `users:admin`.
const DORMANT_REQUIRED_PERMISSION: &str = "users:admin";

/// Actor prefix recorded on the WORM chain when an admin reverts the ML
/// source. Matches the prefix used by `model_swap` so downstream filters
/// see both events in the same admin-action stream.
const AUDIT_ACTOR_SECURITY_ADMIN_PREFIX: &str = "SecurityAdmin";

/// Action recorded on the WORM chain when the ML source is forced
/// dormant via this endpoint. Stable wire string — UI/audit tooling
/// filters on it, paired with `model_swap` from the upload path.
const AUDIT_ACTION_MODEL_DORMANT: &str = "model_dormant";

pub fn initialize() -> Scope {
    web::scope("/ml")
        .route("/status", web::get().to(get_status))
        .route("/models/current", web::get().to(get_current_model))
        .route("/models/current", web::delete().to(delete_current_model))
}

async fn get_status(engine: web::Data<Engine>) -> impl Responder {
    let trackers = engine.trackers();
    let num_trackers = trackers.len();
    let total_flows: usize = trackers.iter().map(|t| t.flow_count()).sum();
    let has_traffic_logger = engine.has_traffic_logger();

    HttpResponse::Ok().json(serde_json::json!({
        "active": true,
        "mode": if has_traffic_logger { "traffic_logging" } else { "inference" },
        "num_trackers": num_trackers,
        "total_flows": total_flows,
        "inference_interval_secs": engine.inference_interval_secs(),
    }))
}

/// `GET /api/ml/models/current` — wire-format snapshot of the ML source
/// state the dashboard's ML Status panel renders.
async fn get_current_model(inference: web::Data<Inference>) -> impl Responder {
    let status = inference.current_status();
    let label = if status.is_active() {
        "active"
    } else if status.is_dormant() {
        "dormant"
    } else {
        "error"
    };
    HttpResponse::Ok().json(serde_json::json!({
        "label": label,
        "status": status,
    }))
}

/// `DELETE /api/ml/models/current` — admin action: force the ML source back
/// to dormant. No-op when already dormant so the client can retry idempotently.
/// Requires `users:admin` (see `DORMANT_REQUIRED_PERMISSION`) and emits a
/// WORM `model_dormant` audit entry capturing the pre-revert state, mirroring
/// the upload path's `model_swap` so both swap-in and revert are auditable.
async fn delete_current_model(
    inference: web::Data<Inference>,
    comm: web::Data<CommunicationManager>,
    claims: AuthClaims,
) -> impl Responder {
    if !claims.permissions.iter().any(|p| p == DORMANT_REQUIRED_PERMISSION) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("model dormant requires the {DORMANT_REQUIRED_PERMISSION} permission"),
        }));
    }

    let before_status = inference.current_status();
    if before_status.is_dormant() {
        return HttpResponse::Ok().json(serde_json::json!({
            "already_dormant": true,
        }));
    }

    inference.swap_state(ModelSourceState::Dormant);

    let audit_detail = serde_json::json!({
        "before": serde_json::to_value(&before_status).unwrap_or(serde_json::Value::Null),
    })
    .to_string();
    let _ = comm
        .publish_event(AuditEvent {
            actor: format!("{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX}@{}", claims.username),
            action: AUDIT_ACTION_MODEL_DORMANT.to_string(),
            detail: audit_detail,
        })
        .await;

    HttpResponse::Ok().json(serde_json::json!({
        "already_dormant": false,
    }))
}
