use std::sync::Arc;

use actix_web::{HttpResponse, Responder, Scope, web};
use arc_swap::ArcSwap;
use macros::log;
use tokio::task;

use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::common::error::codec::CodecError;
use crate::common::log::audit::AuditLog;
use crate::core::inference::engine::Engine;
use crate::core::inference::model_adapter::ModelSourceState;
use crate::core::inference::model_watcher::{ModelReloadOutcome, reload_model_from_disk};
use crate::core::inference::runner::Inference;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX, PERMISSION_USERS_ADMIN};
use crate::infrastructure::model_promotion_deps::ModelPromotionDeps;
use crate::interface::system::audit::AuditRepo;

const MODEL_LIFECYCLE_REQUIRED_PERMISSION: &str = PERMISSION_USERS_ADMIN;
const AUDIT_ACTION_MODEL_DORMANT: &str = "model_dormant";
const AUDIT_ACTION_MODEL_ENABLE: &str = "model_enable";

pub fn initialize() -> Scope {
    web::scope("/ml")
        .route("/status", web::get().to(get_status))
        .route("/models/current", web::get().to(get_current_model))
        .route("/models/current", web::delete().to(delete_current_model))
        .route("/models/current/enable", web::post().to(enable_current_model))
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

async fn get_current_model(inference: web::Data<Inference>) -> impl Responder {
    let status = inference.model_source_status();
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

async fn delete_current_model(
    inference: web::Data<Inference>,
    audit_repo: web::Data<dyn AuditRepo>,
    claims: AuthClaims,
) -> impl Responder {
    if !claims
        .permissions
        .iter()
        .any(|p| p == MODEL_LIFECYCLE_REQUIRED_PERMISSION)
    {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("model dormant requires the {MODEL_LIFECYCLE_REQUIRED_PERMISSION} permission"),
        }));
    }

    let before_status = inference.model_source_status();
    if before_status.is_dormant() {
        return HttpResponse::Ok().json(serde_json::json!({
            "already_dormant": true,
        }));
    }

    let before_json = match serde_json::to_value(&before_status) {
        Ok(value) => value,
        Err(err) => {
            log!(CodecError::SerializeFailed(err));
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "failed to serialize current model status",
            }));
        }
    };

    let audit_detail = serde_json::json!({
        "before": before_json,
    })
    .to_string();
    let audit_actor = format!("{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX}@{}", claims.username);
    if let Err(err) = audit_repo
        .insert_audit_log(&audit_actor, AUDIT_ACTION_MODEL_DORMANT, &audit_detail)
        .await
    {
        log!(AuditLog::AuditDbWriteFailed(
            err.to_string(),
            audit_actor,
            AUDIT_ACTION_MODEL_DORMANT.to_string()
        ));
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "required audit write failed",
        }));
    }
    log!(AuditLog::AuditEvent(
        audit_actor,
        AUDIT_ACTION_MODEL_DORMANT.to_string(),
    ));

    inference.swap_state(ModelSourceState::Dormant);

    HttpResponse::Ok().json(serde_json::json!({
        "already_dormant": false,
    }))
}

async fn enable_current_model(
    inference: web::Data<Inference>,
    app_config: web::Data<ArcSwap<AppConfig>>,
    promotion_deps: web::Data<ModelPromotionDeps>,
    audit_repo: web::Data<dyn AuditRepo>,
    claims: AuthClaims,
) -> impl Responder {
    if !claims
        .permissions
        .iter()
        .any(|p| p == MODEL_LIFECYCLE_REQUIRED_PERMISSION)
    {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("model enable requires the {MODEL_LIFECYCLE_REQUIRED_PERMISSION} permission"),
        }));
    }

    let before_state = inference.model_source_state();
    let before_status = before_state.to_status();
    let before_json = match serde_json::to_value(&before_status) {
        Ok(value) => value,
        Err(err) => {
            log!(CodecError::SerializeFailed(err));
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "failed to serialize current model status",
            }));
        }
    };

    let inference = inference.into_inner();
    let app_config = app_config.into_inner();
    let promotion_deps = promotion_deps.into_inner();
    let reload_inference = Arc::clone(&inference);
    let reload_config = Arc::clone(&app_config);
    let runtime_loader = Arc::clone(&promotion_deps.model_runtime_loader);
    let artifact_resolver = Arc::clone(&promotion_deps.model_artifact_resolver);
    let config_loader = Arc::clone(&promotion_deps.model_config_loader);

    let outcome = match task::spawn_blocking(move || {
        reload_model_from_disk(
            &reload_inference,
            &reload_config,
            runtime_loader.as_ref(),
            artifact_resolver.as_ref(),
            config_loader.as_ref(),
        )
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("model enable task failed: {err}"),
            }));
        }
    };

    match outcome {
        ModelReloadOutcome::Active { info } => {
            let audit_detail = serde_json::json!({
                "before": before_json,
                "after": {
                    "name": info.name(),
                    "adapter_kind": info.adapter_kind(),
                    "loaded_at_secs": info.loaded_at_secs,
                    "features_count": info.features_count(),
                },
            })
            .to_string();
            let audit_actor = format!("{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX}@{}", claims.username);
            if let Err(err) = audit_repo
                .insert_audit_log(&audit_actor, AUDIT_ACTION_MODEL_ENABLE, &audit_detail)
                .await
            {
                inference.swap_state(before_state);
                log!(AuditLog::AuditDbWriteFailed(
                    err.to_string(),
                    audit_actor,
                    AUDIT_ACTION_MODEL_ENABLE.to_string()
                ));
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "required audit write failed",
                }));
            }
            log!(AuditLog::AuditEvent(audit_actor, AUDIT_ACTION_MODEL_ENABLE.to_string(),));

            HttpResponse::Ok().json(serde_json::json!({
                "enabled": true,
                "label": "active",
                "status": inference.model_source_status(),
            }))
        }
        ModelReloadOutcome::Dormant => HttpResponse::NotFound().json(serde_json::json!({
            "enabled": false,
            "label": "dormant",
            "error": "models/manifest.yaml is missing",
            "status": inference.model_source_status(),
        })),
        ModelReloadOutcome::Error {
            msg,
            last_attempted_path,
        } => HttpResponse::UnprocessableEntity().json(serde_json::json!({
            "enabled": false,
            "label": "error",
            "error": msg,
            "last_attempted_path": last_attempted_path,
            "status": inference.model_source_status(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;

    use actix_web::http::StatusCode;
    use async_trait::async_trait;

    use super::*;
    use crate::adapter::model_promotion_store::FsModelPromotionStore;
    use crate::common::error::Error;
    use crate::common::error::database::DatabaseError;
    use crate::core::inference::model_promotion::PromoteGate;
    use crate::core::inference::runner::Inference;
    use crate::domain::common::audit::AuditLogEntry;
    use crate::domain::detection::ml_detection::ClipParams;
    use crate::domain::detection::ml_inference_config::MLInferenceConfig;
    use crate::domain::detection::model_source::ModelSourceStatus;
    use crate::domain::detection::{
        error::MLError,
        manifest::{
            AlertRuleSpec, ArtifactKind, ArtifactSpec, AttackMappingSpec, DetectionRuleSpec, LabelSpec, ModelManifest,
            OutputHeadSpec, OutputRole, OutputSemantic, PipelineOutputSpec, PreprocessingStep, RuntimeSpec,
            StageInputSource, StageInputSpec, StageKind, StageSpec,
        },
    };
    use crate::domain::identity::auth::Claims;
    use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
    use crate::interface::detection::model_config_loader::ModelConfigLoader;
    use crate::interface::detection::model_runtime::{ModelRuntime, ModelRuntimeLoader, RuntimeTensor};

    struct FailingAuditRepo;

    #[async_trait]
    impl AuditRepo for FailingAuditRepo {
        async fn insert_audit_log(&self, _actor: &str, _action: &str, _detail: &str) -> Result<(), Error> {
            Err(DatabaseError::PersistedValueInvalid("audit_log", "detail", "forced").into())
        }

        async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
            Ok(Vec::new())
        }

        async fn list_audit_logs_by_src_ip(&self, _src_ip: &str, _limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
            Ok(Vec::new())
        }

        async fn verify_audit_log_chain(&self, _after_id: i64) -> Result<(usize, i64), Error> {
            Ok((0, 0))
        }
    }

    fn claims() -> AuthClaims {
        AuthClaims(Claims {
            sub: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            permissions: vec![MODEL_LIFECYCLE_REQUIRED_PERMISSION.to_string()],
        })
    }

    fn test_inference_config() -> MLInferenceConfig {
        MLInferenceConfig {
            ae_feature_names: vec!["Destination Port".to_string()],
            ae_clip_params: HashMap::from([(
                "Destination Port".to_string(),
                ClipParams {
                    lower: 0.0,
                    upper: 65_535.0,
                },
            )]),
            ae_scaler_mean: vec![0.0],
            ae_scaler_std: vec![1.0],
            ae_post_clip_min: -5.0,
            ae_post_clip_max: 5.0,
            classifier_feature_names: vec!["Destination Port".to_string()],
            minmax_params: HashMap::new(),
            robust_params: HashMap::new(),
            quantile_params: HashMap::new(),
        }
    }

    fn test_manifest() -> ModelManifest {
        ModelManifest {
            name: "test-model".to_string(),
            version: 1,
            runtime: RuntimeSpec {
                pipeline_mode: "dag".to_string(),
                normal_label: "Normal".to_string(),
            },
            artifacts: vec![
                ArtifactSpec {
                    id: "ae_onnx".to_string(),
                    file: "deep_autoencoder.onnx".to_string(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "classifier_onnx".to_string(),
                    file: "classifier.onnx".to_string(),
                    kind: ArtifactKind::Onnx,
                },
                ArtifactSpec {
                    id: "sidecar".to_string(),
                    file: "sidecar.json".to_string(),
                    kind: ArtifactKind::Sidecar,
                },
            ],
            stages: vec![
                StageSpec {
                    id: "anomaly_detector".to_string(),
                    kind: StageKind::Autoencoder,
                    model_file: "deep_autoencoder.onnx".to_string(),
                    depends_on: vec![],
                    inputs: vec![StageInputSpec {
                        name: "Destination Port".to_string(),
                        source: StageInputSource::Feature,
                        stage: None,
                        output: None,
                    }],
                    preprocessing: vec![PreprocessingStep::StandardScaler {
                        sidecar: "sidecar.json".to_string(),
                    }],
                    output_heads: vec![OutputHeadSpec {
                        name: "ae_anomaly_score".to_string(),
                        index: 0,
                        shape: vec!["1".to_string()],
                        semantic: OutputSemantic::AnomalyScore,
                        threshold: Some(0.5),
                        min_confidence: None,
                    }],
                },
                StageSpec {
                    id: "classifier".to_string(),
                    kind: StageKind::Classifier,
                    model_file: "classifier.onnx".to_string(),
                    depends_on: vec!["anomaly_detector".to_string()],
                    inputs: vec![
                        StageInputSpec {
                            name: "Destination Port".to_string(),
                            source: StageInputSource::Feature,
                            stage: None,
                            output: None,
                        },
                        StageInputSpec {
                            name: "ae_anomaly_score".to_string(),
                            source: StageInputSource::StageOutput,
                            stage: Some("anomaly_detector".to_string()),
                            output: Some("ae_anomaly_score".to_string()),
                        },
                    ],
                    preprocessing: vec![],
                    output_heads: vec![OutputHeadSpec {
                        name: "class_probs".to_string(),
                        index: 0,
                        shape: vec!["2".to_string()],
                        semantic: OutputSemantic::Multiclass,
                        threshold: None,
                        min_confidence: Some(0.4),
                    }],
                },
            ],
            outputs: vec![PipelineOutputSpec {
                stage: "classifier".to_string(),
                output: "class_probs".to_string(),
                alias: Some("class_probs".to_string()),
                role: OutputRole::ClassProbabilities,
            }],
            detection_rules: vec![DetectionRuleSpec::ClassConfidence {
                id: "class_confidence".to_string(),
                output: "class_probs".to_string(),
                attack: AttackMappingSpec::PredictedClass {
                    output: "class_probs".to_string(),
                    exclude_normal: true,
                },
            }],
            labels: BTreeMap::from([(
                "0".to_string(),
                LabelSpec {
                    name: "Bot".to_string(),
                    confirmations: Some(1),
                    playbook: None,
                },
            )]),
            alert_rules: vec![AlertRuleSpec {
                condition: "class_probs.max > min_confidence".to_string(),
                source_label: "class_probs".to_string(),
            }],
        }
    }

    fn inference_with_error_state() -> web::Data<Inference> {
        web::Data::new(Inference::new(
            ModelSourceState::Error {
                msg: "load failed".to_string(),
                since: SystemTime::UNIX_EPOCH,
                last_attempted_path: Some(PathBuf::from("models/manifest.yaml")),
            },
            Arc::new(test_inference_config()),
            Arc::new(ArcSwap::from_pointee(AppConfig::defaults())),
        ))
    }

    struct FakeRuntime;

    impl ModelRuntime for FakeRuntime {
        fn run_stage_batch(
            &self,
            _rows: &[Vec<f32>],
            _batch_size: usize,
            _n_features: usize,
            _stage_kind: StageKind,
            _output_heads: &[OutputHeadSpec],
        ) -> Result<Vec<RuntimeTensor>, MLError> {
            Ok(Vec::new())
        }
    }

    struct FakeRuntimeLoader;

    impl ModelRuntimeLoader for FakeRuntimeLoader {
        fn load(
            &self,
            _model_path: &Path,
            _model_name: &str,
            _features: usize,
            _batch_size: usize,
            _timeout: Duration,
        ) -> Result<Arc<dyn ModelRuntime>, MLError> {
            Ok(Arc::new(FakeRuntime))
        }
    }

    struct FakeArtifactResolver;

    impl ModelArtifactResolver for FakeArtifactResolver {
        fn resolve_model_path(&self, _manifest_path: Option<&Path>, relative_path: &str) -> PathBuf {
            PathBuf::from(relative_path)
        }
    }

    struct FakeConfigLoader;

    impl ModelConfigLoader for FakeConfigLoader {
        fn load_manifest(&self, _manifest_path: &Path) -> Result<ModelManifest, MLError> {
            Ok(test_manifest())
        }

        fn load_manifest_with_sidecar(
            &self,
            _manifest_path: &Path,
        ) -> Result<(MLInferenceConfig, ModelManifest), MLError> {
            Ok((test_inference_config(), test_manifest()))
        }
    }

    fn promotion_deps() -> web::Data<ModelPromotionDeps> {
        web::Data::new(ModelPromotionDeps {
            model_runtime_loader: Arc::new(FakeRuntimeLoader),
            model_artifact_resolver: Arc::new(FakeArtifactResolver),
            model_config_loader: Arc::new(FakeConfigLoader),
            promotion_store: Arc::new(FsModelPromotionStore),
            validation_gate: Arc::new(PromoteGate::new()),
        })
    }

    struct ManifestSentinel {
        path: PathBuf,
        remove_file: bool,
        remove_dir: bool,
    }

    impl Drop for ManifestSentinel {
        fn drop(&mut self) {
            if self.remove_file {
                fs::remove_file(&self.path).ok();
            }
            if self.remove_dir
                && let Some(parent) = self.path.parent()
            {
                fs::remove_dir(parent).ok();
            }
        }
    }

    fn ensure_manifest_sentinel() -> ManifestSentinel {
        let dir = PathBuf::from("models");
        let remove_dir = !dir.exists();
        fs::create_dir_all(&dir).expect("create test models dir");
        let path = dir.join("manifest.yaml");
        let remove_file = !path.exists();
        if remove_file {
            fs::write(&path, b"test manifest sentinel").expect("write test manifest sentinel");
        }
        ManifestSentinel {
            path,
            remove_file,
            remove_dir,
        }
    }

    #[tokio::test]
    async fn delete_current_model_preserves_state_when_required_audit_fails() {
        let inference = inference_with_error_state();
        let audit_repo = web::Data::from(Arc::new(FailingAuditRepo) as Arc<dyn AuditRepo>);
        let req = actix_web::test::TestRequest::default().to_http_request();

        let response = delete_current_model(inference.clone(), audit_repo, claims())
            .await
            .respond_to(&req);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        match inference.model_source_status() {
            ModelSourceStatus::Error { msg, .. } => assert_eq!(msg, "load failed"),
            other => panic!("model state should remain error after audit failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enable_current_model_rolls_back_state_when_required_audit_fails() {
        let _manifest = ensure_manifest_sentinel();
        let inference = inference_with_error_state();
        let audit_repo = web::Data::from(Arc::new(FailingAuditRepo) as Arc<dyn AuditRepo>);
        let app_config = web::Data::from(Arc::new(ArcSwap::from_pointee(AppConfig::defaults())));
        let req = actix_web::test::TestRequest::default().to_http_request();

        let response = enable_current_model(inference.clone(), app_config, promotion_deps(), audit_repo, claims())
            .await
            .respond_to(&req);

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        match inference.model_source_status() {
            ModelSourceStatus::Error { msg, .. } => assert_eq!(msg, "load failed"),
            other => panic!("model state should roll back after audit failure, got {other:?}"),
        }
    }
}
