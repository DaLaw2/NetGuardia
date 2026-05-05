use std::str::FromStr;

use actix_web::{HttpResponse, Scope, web};
use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::adapter::http::helpers::{ok_json_or_error, ok_or_error};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::response::engine::SoarEngine;
use crate::core::response::playbook_service::PlaybookService;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionSource, ThreatDetectedEvent};
use crate::domain::response::playbook_data::{CreateConditionInput, CreatePlaybookInput};

#[derive(Deserialize)]
struct CreatePlaybookRequest {
    name: String,
    trigger_event: String,
    condition_threshold: Option<f64>,
    condition_count: Option<i64>,
    condition_window_secs: Option<i64>,
    cooldown_secs: Option<i64>,
    actions: Vec<CreateActionRequest>,
    conditions: Option<Vec<CreateConditionRequest>>,
}

#[derive(Deserialize)]
struct CreateActionRequest {
    action_type: String,
    params: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct CreateConditionRequest {
    condition_type: String,
    operator: Option<String>,
    value: String,
    value2: Option<String>,
}

fn map_request_to_input(body: &CreatePlaybookRequest, fallback_cooldown: i64) -> CreatePlaybookInput {
    let actions = body
        .actions
        .iter()
        .map(|a| {
            let params_str = a
                .params
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "{}".into()))
                .unwrap_or_else(|| "{}".into());
            (a.action_type.clone(), params_str)
        })
        .collect();

    let conditions = body
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            CreateConditionInput::new(
                c.condition_type.clone(),
                c.operator.clone(),
                c.value.clone(),
                c.value2.clone(),
            )
        })
        .collect();

    CreatePlaybookInput {
        name: body.name.clone(),
        trigger_event: body.trigger_event.clone(),
        condition_threshold: body.condition_threshold,
        condition_count: body.condition_count,
        condition_window_secs: body.condition_window_secs,
        cooldown_secs: body.cooldown_secs.unwrap_or(fallback_cooldown),
        actions,
        conditions,
    }
}

pub fn initialize() -> Scope {
    web::scope("/soar")
        .route("/playbooks", web::get().to(list_playbooks))
        .route("/playbooks", web::post().to(create_playbook))
        .route("/playbooks/{id}", web::put().to(update_playbook))
        .route("/playbooks/{id}", web::delete().to(delete_playbook))
        .route("/playbooks/{id}/toggle", web::post().to(toggle_playbook))
        .route("/blocks", web::get().to(list_active_blocks))
        .route("/blocks/{id}/unblock", web::post().to(manual_unblock))
        .route("/executions", web::get().to(list_executions))
        .route("/whitelist", web::get().to(list_whitelist))
        .route("/whitelist", web::post().to(add_whitelist))
        .route("/whitelist/{ip}", web::delete().to(remove_whitelist))
        .route("/dry-run", web::post().to(dry_run))
}

async fn list_playbooks(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    ok_json_or_error(svc.list_playbooks().await)
}

async fn create_playbook(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    app_config: web::Data<ArcSwap<AppConfig>>,
    body: web::Json<CreatePlaybookRequest>,
) -> HttpResponse {
    let input = map_request_to_input(&body, app_config.load().soar.fallback_cooldown_secs);
    match svc.create_playbook(&input).await {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({"id": id})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn update_playbook(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    app_config: web::Data<ArcSwap<AppConfig>>,
    path: web::Path<i64>,
    body: web::Json<CreatePlaybookRequest>,
) -> HttpResponse {
    let id = path.into_inner();
    let input = map_request_to_input(&body, app_config.load().soar.fallback_cooldown_secs);
    match svc.update_playbook(id, &input).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[derive(Deserialize)]
struct TogglePlaybookRequest {
    enabled: bool,
}

async fn toggle_playbook(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    path: web::Path<i64>,
    body: web::Json<TogglePlaybookRequest>,
) -> HttpResponse {
    match svc.toggle_playbook(path.into_inner(), body.enabled).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_playbook(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<i64>) -> HttpResponse {
    match svc.delete_playbook(path.into_inner()).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_active_blocks(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    ok_json_or_error(svc.list_active_blocks().await)
}

async fn manual_unblock(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<i64>) -> HttpResponse {
    ok_or_error(svc.manual_unblock(path.into_inner()).await)
}

async fn list_executions(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    app_config: web::Data<ArcSwap<AppConfig>>,
) -> HttpResponse {
    ok_json_or_error(svc.list_executions(app_config.load().soar.execution_list_limit).await)
}

async fn list_whitelist(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    ok_json_or_error(svc.list_whitelist().await)
}

#[derive(Deserialize)]
struct WhitelistRequest {
    ip: String,
}

async fn add_whitelist(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    body: web::Json<WhitelistRequest>,
) -> HttpResponse {
    match svc.add_whitelist(&body.ip).await {
        Ok(()) => HttpResponse::Created().json(serde_json::json!({"added": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_whitelist(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<String>) -> HttpResponse {
    ok_or_error(svc.remove_whitelist(&path.into_inner()).await)
}

/// Client shape for `POST /api/soar/dry-run`. Only the fields a SOAR
/// matcher actually reads are carried — `dest_ip`, `protocol`,
/// `packet_rate`, `flow_count` participate in neither trigger-matching
/// nor condition evaluation, so accepting them would just invite
/// confusion. Sensible defaults fill in the rest of the synthetic
/// `ThreatDetectedEvent` body.
#[derive(Deserialize)]
struct DryRunRequest {
    attack_type: String,
    confidence: f32,
    source_ip: String,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    active_source_count: Option<usize>,
    #[serde(default)]
    fused_confidence: Option<f32>,
    #[serde(default)]
    geoip_country: Option<String>,
    #[serde(default)]
    is_repeat_offender: Option<bool>,
}

/// `POST /api/soar/dry-run` — simulate every enabled playbook against
/// a synthetic event. No actions execute, no cooldown or frequency
/// state gets recorded. Useful for an admin who just edited a
/// playbook's conditions and wants to sanity-check the match logic
/// before enabling it.
async fn dry_run(_auth: AuthClaims, engine: web::Data<SoarEngine>, body: web::Json<DryRunRequest>) -> HttpResponse {
    let event = match build_event(body.into_inner()) {
        Ok(e) => e,
        Err(msg) => {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": msg }));
        }
    };
    let matches = engine.dry_run(&event);
    HttpResponse::Ok().json(serde_json::json!({
        "match_count": matches.iter().filter(|m| m.would_fire).count(),
        "playbooks_evaluated": matches.len(),
        "results": matches,
    }))
}

/// Translate a wire `DryRunRequest` into a synthetic `ThreatDetectedEvent`.
/// Errors on typo'd `DetectionSource` names so an admin dry-running a
/// `SingleSourceHigh` condition doesn't silently get an empty sources
/// vector and a "doesn't match" result they misread as the playbook
/// being broken.
fn build_event(req: DryRunRequest) -> Result<ThreatDetectedEvent, String> {
    let sources: Vec<DetectionSource> = match req.sources {
        Some(names) => names
            .iter()
            .map(|n| DetectionSource::from_str(n).map_err(|_| format!("unknown DetectionSource: {n}")))
            .collect::<Result<Vec<_>, _>>()?,
        None => vec![DetectionSource::ML],
    };
    if sources.is_empty() {
        return Err("sources[] must contain at least one DetectionSource (send null to default to [ML])".to_string());
    }
    let active_source_count = req.active_source_count.unwrap_or(sources.len());
    let fused_confidence = req.fused_confidence.unwrap_or(req.confidence);
    Ok(ThreatDetectedEvent {
        attack_type: req.attack_type,
        confidence: req.confidence,
        source_ip: req.source_ip,
        dest_ip: "0.0.0.0".to_string(),
        flow_count: 1,
        packet_rate: 0.0,
        protocol: 6,
        geoip_country: req.geoip_country,
        is_repeat_offender: req.is_repeat_offender.unwrap_or(false),
        sources,
        active_source_count,
        fused_confidence,
        ae_score: 0.0,
        anomaly_score: 0.0,
        c2_score: 0.0,
    })
}
