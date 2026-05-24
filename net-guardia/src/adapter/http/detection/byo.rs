use std::path::PathBuf;
use std::time::Duration;

use actix_multipart::Multipart;
use actix_web::{HttpResponse, Scope, web};
use arc_swap::ArcSwap;
use serde::Serialize;
use uuid::Uuid;

use crate::adapter::http::detection::model_upload::{
    UploadCaps, UploadSummary, cleanup_staging_dir, ingest_multipart, structured_error_response,
};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::inference::model_promotion::{
    ModelValidationReport, PromoteError, StagedModelValidation, validate_staged_model,
};
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::PERMISSION_USERS_ADMIN;
use crate::domain::detection::feature_extractor::feature_registry_names;
use crate::domain::detection::manifest::{
    ARTIFACT_KINDS, ATTACK_MAPPING_SOURCES, DETECTION_RULE_TYPES, MANIFEST_VERSION, OUTPUT_ROLES, OUTPUT_SEMANTICS,
    PREPROCESSING_TYPES, REQUIRED_MANIFEST_SECTIONS, RUNTIME_ADAPTERS, STAGE_INPUT_SOURCES, STAGE_KINDS,
};
use crate::domain::detection::model_files::{MODELS_DIR, STAGING_SUBDIR};
use crate::infrastructure::model_promotion_deps::ModelPromotionDeps;

const VALIDATE_REQUIRED_PERMISSION: &str = PERMISSION_USERS_ADMIN;

pub fn initialize() -> Scope {
    web::scope("/byo")
        .route("/feature-registry", web::get().to(get_feature_registry))
        .route("/schema", web::get().to(get_schema))
        .route("/validate", web::post().to(validate_bundle))
}

async fn get_feature_registry(_auth: AuthClaims) -> HttpResponse {
    let names = feature_registry_names();
    HttpResponse::Ok().json(serde_json::json!({
        "count": names.len(),
        "entries": names.iter().map(|name| FeatureEntry {
            name,
            value_type: "f32",
            unit: None,
            description: None,
            stability: "stable",
        }).collect::<Vec<_>>(),
    }))
}

async fn get_schema(_auth: AuthClaims, app_config: web::Data<ArcSwap<AppConfig>>) -> HttpResponse {
    let config = app_config.load();
    let caps = UploadCaps::from_config(&config);
    HttpResponse::Ok().json(serde_json::json!({
        "manifest_version": MANIFEST_VERSION,
        "bundle": {
            "field": "bundle",
            "format": "zip",
            "required_files": ["manifest.yaml", "inference_config.json"],
            "model_file_extensions": [".onnx"],
        },
        "limits": {
            "bundle_bytes": caps.bundle,
            "manifest_bytes": caps.manifest,
            "onnx_bytes": caps.onnx,
            "sidecar_bytes": caps.scaler,
        },
        "preprocessing": PREPROCESSING_TYPES,
        "output_semantics": OUTPUT_SEMANTICS,
        "output_roles": OUTPUT_ROLES,
        "detection_rule_types": DETECTION_RULE_TYPES,
        "attack_mapping_sources": ATTACK_MAPPING_SOURCES,
        "runtime_adapters": RUNTIME_ADAPTERS,
        "runtime": {
            "pipeline_mode": "dag",
            "normal_label": "Normal"
        },
        "required_manifest_sections": REQUIRED_MANIFEST_SECTIONS,
        "artifact_kinds": ARTIFACT_KINDS,
        "stage_kinds": STAGE_KINDS,
        "stage_input_sources": STAGE_INPUT_SOURCES,
        "notes": [
            "Only manifest version 1 is accepted.",
            "Pipeline topology is declared by stages.depends_on and stage_output inputs.",
            "inference_config.json is a preprocessing sidecar; runtime topology, labels, thresholds, and output mapping come from manifest.yaml."
        ],
    }))
}

async fn validate_bundle(
    app_config: web::Data<ArcSwap<AppConfig>>,
    promotion_deps: web::Data<ModelPromotionDeps>,
    claims: AuthClaims,
    payload: Multipart,
) -> HttpResponse {
    if !claims.permissions.iter().any(|p| p == VALIDATE_REQUIRED_PERMISSION) {
        return structured_error_response(
            403,
            "permission_denied",
            "authorization",
            format!("model validation requires the {VALIDATE_REQUIRED_PERMISSION} permission"),
            "Sign in as an administrator and retry validation.",
        );
    }

    let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
    let staging_id = Uuid::new_v4().to_string();
    let staging_dir = staging_root.join(&staging_id);

    let config = app_config.load();
    let caps = UploadCaps::from_config(&config);
    let batch_size = config.ml.inference.inference_batch_size;
    let onnx_load_timeout = Duration::from_secs(config.ml.inference.onnx_load_timeout_secs);
    drop(config);

    let summary = match ingest_multipart(payload, &staging_dir, caps).await {
        Ok(value) => value,
        Err(err) => {
            cleanup_staging_dir(&staging_dir).await;
            return err.into_response();
        }
    };

    let outcome = validate_staged_model(&StagedModelValidation {
        staging_dir: &staging_dir,
        batch_size,
        onnx_load_timeout,
        validation_gate: Some(promotion_deps.validation_gate.as_ref()),
        model_runtime_loader: promotion_deps.model_runtime_loader.as_ref(),
        model_artifact_resolver: promotion_deps.model_artifact_resolver.as_ref(),
        model_config_loader: promotion_deps.model_config_loader.as_ref(),
        promotion_store: promotion_deps.promotion_store.as_ref(),
    })
    .await;
    cleanup_staging_dir(&staging_dir).await;

    match outcome {
        Ok(report) => validation_ok_response(staging_id, &summary, report),
        Err(err) => validation_failed_response(staging_id, &summary, err),
    }
}

fn validation_ok_response(staging_id: String, summary: &UploadSummary, report: ModelValidationReport) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "valid": true,
        "staging_id": staging_id,
        "artifact_summary": {
            "bundle_bytes": summary.bundle_bytes,
            "manifest_bytes": summary.manifest_bytes,
            "onnx_bytes": summary.onnx_bytes,
            "scaler_bytes": summary.scaler_bytes,
            "manifest_name": report.manifest_name,
            "adapter_kind": report.adapter_kind,
            "manifest_sha256": report.manifest_sha256,
            "artifacts": report.artifacts,
        },
        "diagnostics": [validation_diagnostic(
            "info",
            "validation_passed",
            "bundle",
            "Bundle validation passed.",
            "This bundle can be promoted.",
        )],
    }))
}

fn validation_failed_response(staging_id: String, summary: &UploadSummary, err: PromoteError) -> HttpResponse {
    let diagnostic = diagnostic_from_promote_error(err);
    HttpResponse::Ok().json(serde_json::json!({
        "valid": false,
        "staging_id": staging_id,
        "artifact_summary": {
            "bundle_bytes": summary.bundle_bytes,
            "manifest_bytes": summary.manifest_bytes,
            "onnx_bytes": summary.onnx_bytes,
            "scaler_bytes": summary.scaler_bytes,
        },
        "diagnostics": [diagnostic],
    }))
}

fn diagnostic_from_promote_error(err: PromoteError) -> ValidationDiagnostic {
    match err {
        PromoteError::ManifestInvalid { err } => validation_diagnostic(
            "error",
            "manifest_invalid",
            "manifest.yaml",
            format!("Manifest is invalid: {err}"),
            "Fix manifest.yaml and validate again.",
        ),
        PromoteError::ValidationFailed { err } => validation_diagnostic(
            "error",
            "model_validation_failed",
            "bundle",
            format!("Model failed validation: {err}"),
            "Check manifest, sidecar, feature order, and ONNX runtime contract.",
        ),
        PromoteError::StagingIo { operation, err } => validation_diagnostic(
            "error",
            "staging_io_failed",
            "bundle",
            format!("Staging IO failed during {operation}: {err}"),
            "Check server storage permissions and available space.",
        ),
        PromoteError::PromoteIo { operation, err } => validation_diagnostic(
            "error",
            "promotion_io_failed",
            "bundle",
            format!("Promotion IO failed during {operation}: {err}"),
            "Retry validation after checking server logs.",
        ),
        PromoteError::AuditDetailSerialize { err } => validation_diagnostic(
            "error",
            "audit_detail_serialize_failed",
            "audit",
            format!("Audit detail serialization failed: {err}"),
            "Retry after checking server logs.",
        ),
        PromoteError::AuditWrite { err } => validation_diagnostic(
            "error",
            "audit_write_failed",
            "audit",
            format!("Audit write failed: {err}"),
            "Check database health before promotion.",
        ),
        PromoteError::ConcurrentPromote => validation_diagnostic(
            "warning",
            "concurrent_promote",
            "bundle",
            "Another model promote is already in progress.",
            "Wait for the current promotion to finish and retry.",
        ),
        PromoteError::ConcurrentValidation => validation_diagnostic(
            "warning",
            "concurrent_validation",
            "bundle",
            "Another model validation is already in progress.",
            "Wait for the current validation to finish and retry.",
        ),
    }
}

fn validation_diagnostic(
    severity: &str,
    code: &str,
    path: &str,
    message: impl Into<String>,
    hint: &str,
) -> ValidationDiagnostic {
    ValidationDiagnostic {
        severity: severity.to_string(),
        code: code.to_string(),
        path: path.to_string(),
        message: message.into(),
        hint: hint.to_string(),
    }
}

#[derive(Serialize)]
struct FeatureEntry<'a> {
    name: &'a str,
    value_type: &'a str,
    unit: Option<&'a str>,
    description: Option<&'a str>,
    stability: &'a str,
}

#[derive(Serialize)]
struct ValidationDiagnostic {
    severity: String,
    code: String,
    path: String,
    message: String,
    hint: String,
}
