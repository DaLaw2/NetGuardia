use std::str::FromStr;

use actix_web::{HttpResponse, Scope, web};
use arc_swap::ArcSwap;
use serde::Deserialize;

use crate::adapter::http::helpers::{bad_request, internal_error, not_found, ok_json_or_error, ok_or_error};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::common::error::Error;
use crate::common::error::codec::CodecError;
use crate::core::response::engine::SoarEngine;
use crate::core::response::playbook_service::PlaybookService;
use crate::domain::common::config::AppConfig;
use crate::domain::common::event::{DetectionSource, ThreatDetectedEvent};
use crate::domain::data_plane::error::EbpfError;
use crate::domain::response::playbook_validator;
use crate::interface::response::playbook_data::{ActionInput, CreateConditionInput, CreatePlaybookInput};

const DEFAULT_DRY_RUN_DEST_IP: &str = "0.0.0.0";
const DEFAULT_DRY_RUN_FLOW_COUNT: u32 = 1;
const DEFAULT_DRY_RUN_PACKET_RATE: f64 = 0.0;
const DEFAULT_DRY_RUN_PROTOCOL: u8 = 6;

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

fn map_request_to_input(
    body: &CreatePlaybookRequest,
    fallback_cooldown: i64,
    max_ttl_secs: u64,
) -> Result<CreatePlaybookInput, String> {
    playbook_validator::validate_optional_positive_i64("condition_count", body.condition_count)
        .map_err(|e| e.to_string())?;
    playbook_validator::validate_optional_positive_i64("condition_window_secs", body.condition_window_secs)
        .map_err(|e| e.to_string())?;
    let cooldown_secs = body.cooldown_secs.unwrap_or(fallback_cooldown);
    playbook_validator::validate_cooldown_secs(cooldown_secs).map_err(|e| e.to_string())?;

    let actions = body
        .actions
        .iter()
        .enumerate()
        .map(|(index, a)| {
            playbook_validator::validate_action(&a.action_type, a.params.as_ref(), max_ttl_secs)
                .map_err(|e| e.to_string())?;
            let params_str = a
                .params
                .as_ref()
                .map(|v| serde_json::to_string(v).map_err(|err| CodecError::SerializeFailed(err).to_string()))
                .transpose()?
                .unwrap_or_else(|| "{}".into());
            Ok(ActionInput {
                action_order: (index + 1) as i64,
                action_type: a.action_type.clone(),
                params_json: params_str,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let conditions = body
        .conditions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| {
            let input = CreateConditionInput::new(
                c.condition_type.clone(),
                c.operator.clone(),
                c.value.clone(),
                c.value2.clone(),
            )
            .map_err(|_| format!("unknown condition_type: {}", c.condition_type))?;
            playbook_validator::validate_condition_input(&input).map_err(|e| e.to_string())?;
            Ok(input)
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(CreatePlaybookInput {
        name: body.name.clone(),
        trigger_event: body.trigger_event.clone(),
        condition_threshold: body.condition_threshold,
        condition_count: body.condition_count,
        condition_window_secs: body.condition_window_secs,
        cooldown_secs,
        actions,
        conditions,
    })
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
    let soar_cfg = app_config.load().soar.clone();
    let input = match map_request_to_input(&body, soar_cfg.fallback_cooldown_secs, soar_cfg.max_ttl_secs) {
        Ok(input) => input,
        Err(e) => return bad_request(e),
    };
    match svc.create_playbook(&input).await {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({"id": id})),
        Err(e) => internal_error(e),
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
    let soar_cfg = app_config.load().soar.clone();
    let input = match map_request_to_input(&body, soar_cfg.fallback_cooldown_secs, soar_cfg.max_ttl_secs) {
        Ok(input) => input,
        Err(e) => return bad_request(e),
    };
    match svc.update_playbook(id, &input).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"updated": true})),
        Ok(false) => not_found("Playbook not found"),
        Err(e) => internal_error(e),
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
        Ok(false) => not_found("Playbook not found"),
        Err(e) => internal_error(e),
    }
}

async fn delete_playbook(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<i64>) -> HttpResponse {
    match svc.delete_playbook(path.into_inner()).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => not_found("Playbook not found"),
        Err(e) => internal_error(e),
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
        Err(e) => whitelist_error(e),
    }
}

async fn remove_whitelist(_auth: AuthClaims, svc: web::Data<PlaybookService>, path: web::Path<String>) -> HttpResponse {
    match svc.remove_whitelist(&path.into_inner()).await {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(e) => whitelist_error(e),
    }
}

fn whitelist_error(error: Error) -> HttpResponse {
    match &error {
        Error::Ebpf(EbpfError::InvalidIpAddress { .. }) => bad_request(error),
        _ => internal_error(error),
    }
}

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

async fn dry_run(_auth: AuthClaims, engine: web::Data<SoarEngine>, body: web::Json<DryRunRequest>) -> HttpResponse {
    let event = match build_event(body.into_inner()) {
        Ok(e) => e,
        Err(msg) => {
            return bad_request(msg);
        }
    };
    let matches = engine.dry_run(&event);
    HttpResponse::Ok().json(serde_json::json!({
        "match_count": matches.iter().filter(|m| m.would_fire).count(),
        "playbooks_evaluated": matches.len(),
        "results": matches,
    }))
}

fn build_event(req: DryRunRequest) -> Result<ThreatDetectedEvent, String> {
    let sources = parse_dry_run_sources(req.sources)?;
    let active_source_count = resolve_dry_run_active_source_count(req.active_source_count, sources.len())?;
    let fused_confidence = req.fused_confidence.unwrap_or(req.confidence);

    Ok(ThreatDetectedEvent {
        attack_type: req.attack_type,
        confidence: req.confidence,
        source_ip: req.source_ip,
        dest_ip: DEFAULT_DRY_RUN_DEST_IP.to_string(),
        flow_count: DEFAULT_DRY_RUN_FLOW_COUNT,
        packet_rate: DEFAULT_DRY_RUN_PACKET_RATE,
        protocol: DEFAULT_DRY_RUN_PROTOCOL,
        geoip_country: req.geoip_country,
        is_repeat_offender: req.is_repeat_offender.unwrap_or(false),
        sources,
        active_source_count,
        fused_confidence,
        diagnostics: Vec::new(),
    })
}

fn parse_dry_run_sources(names: Option<Vec<String>>) -> Result<Vec<DetectionSource>, String> {
    let sources = match names {
        Some(names) => names
            .iter()
            .map(|name| DetectionSource::from_str(name).map_err(|_| format!("unknown DetectionSource: {name}")))
            .collect::<Result<Vec<_>, _>>()?,
        None => vec![DetectionSource::ML],
    };

    if sources.is_empty() {
        return Err("sources[] must contain at least one DetectionSource (send null to default to [ML])".to_string());
    }

    Ok(sources)
}

fn resolve_dry_run_active_source_count(
    active_source_count: Option<usize>,
    sources_len: usize,
) -> Result<usize, String> {
    let active_source_count = active_source_count.unwrap_or(sources_len);
    if active_source_count != sources_len {
        return Err(format!(
            "active_source_count must match sources.len() for dry-run events (got {active_source_count}, expected {sources_len})"
        ));
    }

    Ok(active_source_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn playbook_request() -> CreatePlaybookRequest {
        CreatePlaybookRequest {
            name: "block scan".to_string(),
            trigger_event: "port_scan".to_string(),
            condition_threshold: None,
            condition_count: None,
            condition_window_secs: None,
            cooldown_secs: Some(60),
            actions: vec![CreateActionRequest {
                action_type: "block_ip".to_string(),
                params: None,
            }],
            conditions: None,
        }
    }

    fn input_error(req: &CreatePlaybookRequest) -> String {
        match map_request_to_input(req, 300, 3_600) {
            Ok(_) => panic!("expected playbook input validation error"),
            Err(err) => err,
        }
    }

    fn dry_run_request(sources: Option<Vec<String>>, active_source_count: Option<usize>) -> DryRunRequest {
        DryRunRequest {
            attack_type: "c2".to_string(),
            confidence: 0.9,
            source_ip: "192.0.2.10".to_string(),
            sources,
            active_source_count,
            fused_confidence: None,
            geoip_country: None,
            is_repeat_offender: None,
        }
    }

    #[test]
    fn map_request_rejects_negative_cooldown() {
        let mut req = playbook_request();
        req.cooldown_secs = Some(-1);

        let err = input_error(&req);

        assert_eq!(err, "cooldown_secs must be greater than or equal to 0");
    }

    #[test]
    fn map_request_rejects_non_positive_condition_windows() {
        let mut req = playbook_request();
        req.condition_count = Some(0);

        let err = input_error(&req);

        assert_eq!(err, "condition_count must be greater than 0");

        req.condition_count = Some(1);
        req.condition_window_secs = Some(-1);
        let err = input_error(&req);

        assert_eq!(err, "condition_window_secs must be greater than 0");
    }

    #[test]
    fn map_request_rejects_invalid_action_params() {
        let mut req = playbook_request();
        req.actions[0].params = Some(serde_json::json!({"ttl_secs": 0}));

        let err = input_error(&req);

        assert_eq!(err, "ttl_secs must be greater than 0");

        req.actions[0].params = Some(serde_json::json!({"ttl_secs": 3_601}));
        let err = input_error(&req);

        assert_eq!(err, "ttl_secs must be less than or equal to 3600");
    }

    #[test]
    fn map_request_rejects_unknown_action_type() {
        let mut req = playbook_request();
        req.actions[0].action_type = "typo".to_string();

        let err = input_error(&req);

        assert_eq!(err, "unknown action_type: typo");
    }

    #[test]
    fn map_request_rejects_unknown_condition_type() {
        let mut req = playbook_request();
        req.conditions = Some(vec![CreateConditionRequest {
            condition_type: "typo".to_string(),
            operator: None,
            value: "0.9".to_string(),
            value2: None,
        }]);

        let err = input_error(&req);

        assert_eq!(err, "unknown condition_type: typo");
    }

    #[test]
    fn map_request_rejects_invalid_condition_operator() {
        let mut req = playbook_request();
        req.conditions = Some(vec![CreateConditionRequest {
            condition_type: "threshold".to_string(),
            operator: Some("in".to_string()),
            value: "0.9".to_string(),
            value2: None,
        }]);

        let err = input_error(&req);

        assert_eq!(err, "invalid operator 'in' for condition_type 'threshold'");
    }

    #[test]
    fn map_request_rejects_invalid_condition_values() {
        let cases = [
            ("threshold", "not-a-number", "threshold value must be a finite number"),
            ("frequency", "0", "frequency value must be a positive integer"),
            (
                "ip_pattern",
                "not-cidr",
                "ip_pattern value must be a valid CIDR: not-cidr",
            ),
            (
                "repeat_offender",
                "maybe",
                "repeat_offender value must be 'true' or 'false'",
            ),
            (
                "single_source_high",
                "UnknownSource",
                "single_source_high value must be a valid DetectionSource: UnknownSource",
            ),
        ];

        for (condition_type, value, expected) in cases {
            let mut req = playbook_request();
            req.conditions = Some(vec![CreateConditionRequest {
                condition_type: condition_type.to_string(),
                operator: None,
                value: value.to_string(),
                value2: None,
            }]);

            let err = input_error(&req);

            assert_eq!(err, expected);
        }
    }

    #[test]
    fn map_request_accepts_false_repeat_offender_condition() {
        let mut req = playbook_request();
        req.conditions = Some(vec![CreateConditionRequest {
            condition_type: "repeat_offender".to_string(),
            operator: None,
            value: "false".to_string(),
            value2: None,
        }]);

        let input = map_request_to_input(&req, 300, 3_600).expect("valid repeat_offender false condition");

        assert_eq!(input.conditions[0].value, "false");
    }

    #[test]
    fn map_request_rejects_invalid_webhook_params() {
        let mut req = playbook_request();
        req.actions[0].action_type = "webhook".to_string();
        req.actions[0].params = Some(serde_json::json!({"timeout_secs": 0}));

        let err = input_error(&req);

        assert_eq!(err, "url is required");

        req.actions[0].params = Some(serde_json::json!({"url": "https://example.test/hook", "timeout_secs": 0}));
        let err = input_error(&req);

        assert_eq!(err, "timeout_secs must be greater than 0");
    }

    #[test]
    fn build_event_defaults_active_source_count_from_sources() {
        let req = dry_run_request(Some(vec!["ML".to_string(), "Suricata".to_string()]), None);
        let event = build_event(req).unwrap();
        assert_eq!(event.active_source_count, 2);
        assert_eq!(event.sources, vec![DetectionSource::ML, DetectionSource::Suricata]);
    }

    #[test]
    fn build_event_rejects_active_source_count_mismatch() {
        let req = dry_run_request(Some(vec!["ML".to_string(), "Suricata".to_string()]), Some(1));
        let err = build_event(req).unwrap_err();
        assert!(err.contains("active_source_count must match sources.len()"));
    }

    #[test]
    fn build_event_rejects_unknown_detection_source() {
        let req = dry_run_request(Some(vec!["ML".to_string(), "typo".to_string()]), None);
        let err = build_event(req).unwrap_err();
        assert_eq!(err, "unknown DetectionSource: typo");
    }

    #[test]
    fn whitelist_invalid_ip_errors_are_bad_requests() {
        let response = whitelist_error(EbpfError::InvalidIpAddress("not an ip".to_string()).into());

        assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }
}
