use std::str::FromStr;

use actix_web::{HttpResponse, Scope, web};
use serde::Deserialize;

use crate::core::auth::extractor::AuthClaims;
use crate::core::playbook_service::PlaybookService;
use crate::core::soar::engine::SoarEngine;
use crate::model::event::{DetectionSource, ThreatDetectedEvent};
use crate::model::soar::playbook_data::{CreateConditionInput, CreatePlaybookInput};

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
    match svc.list_playbooks() {
        Ok(playbooks) => {
            let responses: Vec<serde_json::Value> = playbooks
                .into_iter()
                .map(|pb| {
                    let actions: Vec<serde_json::Value> = pb
                        .actions
                        .into_iter()
                        .map(|a| {
                            serde_json::json!({
                                "id": a.id,
                                "action_order": a.action_order,
                                "action_type": a.action_type,
                                "params": a.params,
                            })
                        })
                        .collect();
                    let conditions: Vec<serde_json::Value> = pb
                        .conditions
                        .into_iter()
                        .map(|c| {
                            serde_json::json!({
                                "id": c.id,
                                "condition_type": c.condition_type,
                                "operator": c.operator,
                                "value": c.value,
                                "value2": c.value2,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "id": pb.id,
                        "name": pb.name,
                        "enabled": pb.enabled,
                        "trigger_event": pb.trigger_event,
                        "condition_threshold": pb.condition_threshold,
                        "condition_count": pb.condition_count,
                        "condition_window_secs": pb.condition_window_secs,
                        "cooldown_secs": pb.cooldown_secs,
                        "actions": actions,
                        "conditions": conditions,
                    })
                })
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn create_playbook(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    body: web::Json<CreatePlaybookRequest>,
) -> HttpResponse {
    let actions: Vec<(String, String)> = body
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

    let conditions: Vec<CreateConditionInput> = body
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            let default_op = match c.condition_type.as_str() {
                "threshold" | "frequency" => ">=",
                "source_country" | "ip_pattern" => "in",
                "repeat_offender" => "==",
                _ => ">=",
            };
            CreateConditionInput {
                condition_type: c.condition_type.clone(),
                operator: c.operator.clone().unwrap_or_else(|| default_op.to_string()),
                value: c.value.clone(),
                value2: c.value2.clone(),
            }
        })
        .collect();

    let input = CreatePlaybookInput {
        name: body.name.clone(),
        trigger_event: body.trigger_event.clone(),
        condition_threshold: body.condition_threshold,
        condition_count: body.condition_count,
        condition_window_secs: body.condition_window_secs,
        cooldown_secs: body.cooldown_secs.unwrap_or(300),
        actions,
        conditions,
    };

    match svc.create_playbook(&input) {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({"id": id})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn update_playbook(
    _auth: AuthClaims,
    svc: web::Data<PlaybookService>,
    path: web::Path<i64>,
    body: web::Json<CreatePlaybookRequest>,
) -> HttpResponse {
    let id = path.into_inner();

    let actions: Vec<(String, String)> = body
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

    let conditions: Vec<CreateConditionInput> = body
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            let default_op = match c.condition_type.as_str() {
                "threshold" | "frequency" => ">=",
                "source_country" | "ip_pattern" => "in",
                "repeat_offender" => "==",
                _ => ">=",
            };
            CreateConditionInput {
                condition_type: c.condition_type.clone(),
                operator: c.operator.clone().unwrap_or_else(|| default_op.to_string()),
                value: c.value.clone(),
                value2: c.value2.clone(),
            }
        })
        .collect();

    let input = CreatePlaybookInput {
        name: body.name.clone(),
        trigger_event: body.trigger_event.clone(),
        condition_threshold: body.condition_threshold,
        condition_count: body.condition_count,
        condition_window_secs: body.condition_window_secs,
        cooldown_secs: body.cooldown_secs.unwrap_or(300),
        actions,
        conditions,
    };

    match svc.update_playbook(id, &input) {
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
    match svc.toggle_playbook(path.into_inner(), body.enabled) {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_playbook(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<i64>) -> HttpResponse {
    match svc.delete_playbook(path.into_inner()) {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Playbook not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_active_blocks(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    match svc.list_active_blocks() {
        Ok(blocks) => {
            let responses: Vec<serde_json::Value> = blocks
                .into_iter()
                .map(|b| {
                    serde_json::json!({
                        "id": b.id,
                        "source_ip": b.source_ip,
                        "playbook_id": b.playbook_id,
                        "expires_at": b.expires_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn manual_unblock(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<i64>) -> HttpResponse {
    match svc.manual_unblock(path.into_inner()).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"unblocked": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_executions(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    match svc.list_executions(100) {
        Ok(executions) => {
            let responses: Vec<serde_json::Value> = executions
                .into_iter()
                .map(|ex| {
                    serde_json::json!({
                        "id": ex.id,
                        "playbook_id": ex.playbook_id,
                        "source_ip": ex.source_ip,
                        "trigger_event": ex.trigger_event,
                        "actions_executed": ex.actions_executed,
                        "created_at": ex.created_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_whitelist(_auth: AuthClaims, svc: web::Data<PlaybookService>) -> HttpResponse {
    match svc.list_whitelist() {
        Ok(ips) => HttpResponse::Ok().json(ips),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
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
    match svc.add_whitelist(&body.ip) {
        Ok(()) => HttpResponse::Created().json(serde_json::json!({"added": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn remove_whitelist(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<String>) -> HttpResponse {
    match svc.remove_whitelist(&path.into_inner()) {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({"removed": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
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
