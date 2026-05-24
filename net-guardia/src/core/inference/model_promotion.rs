use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use macros::{log, traceable};
use uuid::Uuid;

use crate::common::log::audit::AuditLog;
use crate::core::inference::model_loader::build_adapter;
use crate::core::inference::runner::Inference;
use crate::domain::common::config::constants::AUDIT_ACTOR_SECURITY_ADMIN_PREFIX;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::manifest::{ModelManifest, preprocessing_sidecar};
use crate::domain::detection::model_files::{MANIFEST_FILENAME, MODELS_DIR};
use crate::interface::detection::model_artifact_resolver::ModelArtifactResolver;
use crate::interface::detection::model_config_loader::ModelConfigLoader;
use crate::interface::detection::model_promotion_store::ModelPromotionStore;
use crate::interface::detection::model_runtime::ModelRuntimeLoader;
use crate::interface::system::audit::AuditRepo;

const AUDIT_ACTION_MODEL_SWAP: &str = "model_swap";

#[derive(Default)]
pub struct PromoteGate {
    in_progress: AtomicBool,
}

impl PromoteGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_acquire(&self) -> Option<PromoteGuard<'_>> {
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(PromoteGuard { gate: self })
        } else {
            None
        }
    }
}

pub struct PromoteGuard<'a> {
    gate: &'a PromoteGate,
}

impl Drop for PromoteGuard<'_> {
    fn drop(&mut self) {
        self.gate.in_progress.store(false, Ordering::Release);
    }
}

pub struct StagedModelPromotion<'a> {
    pub staging_dir: &'a Path,
    pub inference: &'a Inference,
    pub audit_repo: &'a dyn AuditRepo,
    pub promote_gate: &'a PromoteGate,
    pub validation_gate: &'a PromoteGate,
    pub actor_username: &'a str,
    pub batch_size: usize,
    pub onnx_load_timeout: Duration,
    pub model_runtime_loader: &'a dyn ModelRuntimeLoader,
    pub model_artifact_resolver: &'a dyn ModelArtifactResolver,
    pub model_config_loader: &'a dyn ModelConfigLoader,
    pub promotion_store: &'a dyn ModelPromotionStore,
}

pub struct StagedModelValidation<'a> {
    pub staging_dir: &'a Path,
    pub batch_size: usize,
    pub onnx_load_timeout: Duration,
    pub validation_gate: Option<&'a PromoteGate>,
    pub model_runtime_loader: &'a dyn ModelRuntimeLoader,
    pub model_artifact_resolver: &'a dyn ModelArtifactResolver,
    pub model_config_loader: &'a dyn ModelConfigLoader,
    pub promotion_store: &'a dyn ModelPromotionStore,
}

pub async fn validate_staged_model(ctx: &StagedModelValidation<'_>) -> Result<ModelValidationReport, PromoteError> {
    let _validation_guard = match ctx.validation_gate {
        Some(gate) => Some(gate.try_acquire().ok_or(PromoteError::ConcurrentValidation)?),
        None => None,
    };
    let staging_manifest = ctx.staging_dir.join(MANIFEST_FILENAME);

    let manifest_preview = ctx
        .model_config_loader
        .load_manifest(&staging_manifest)
        .map_err(PromoteError::ManifestInvalid)?;

    if manifest_preview.stages.is_empty() {
        return Err(PromoteError::ManifestInvalid(
            "manifest requires at least one stage".to_string(),
        ));
    }
    let artifacts = collect_manifest_artifacts(ctx.staging_dir, &PathBuf::from(MODELS_DIR), &manifest_preview)?;

    let (config, manifest) = ctx
        .model_config_loader
        .load_manifest_with_sidecar(&staging_manifest)
        .map_err(PromoteError::ValidationFailed)?;
    let _adapter = build_adapter(
        &manifest,
        Some(&staging_manifest),
        &config,
        ctx.batch_size,
        ctx.onnx_load_timeout,
        ctx.model_runtime_loader,
        ctx.model_artifact_resolver,
    )
    .map_err(PromoteError::ValidationFailed)?;

    let manifest_sha256 = ctx
        .promotion_store
        .sha256_file(&staging_manifest)
        .await
        .map_err(|e| PromoteError::StagingIo("sha256 manifest", e))?;

    let mut artifact_reports = Vec::with_capacity(artifacts.len());
    for artifact in &artifacts {
        let sha256 = ctx
            .promotion_store
            .sha256_file(&artifact.staged)
            .await
            .map_err(|e| PromoteError::StagingIo(format!("sha256 {}", artifact.file), e))?;
        artifact_reports.push(ArtifactDigest {
            file: artifact.file.clone(),
            kind: artifact.kind.clone(),
            sha256,
        });
    }

    Ok(ModelValidationReport {
        manifest_name: manifest.name.clone(),
        adapter_kind: manifest.runtime_adapter().to_string(),
        manifest_sha256,
        artifacts: artifact_reports,
    })
}

pub async fn validate_and_promote(ctx: &StagedModelPromotion<'_>) -> Result<ModelValidationReport, PromoteError> {
    let guard = ctx.promote_gate.try_acquire().ok_or(PromoteError::ConcurrentPromote)?;
    let validation = validate_staged_model(&StagedModelValidation {
        staging_dir: ctx.staging_dir,
        batch_size: ctx.batch_size,
        onnx_load_timeout: ctx.onnx_load_timeout,
        validation_gate: Some(ctx.validation_gate),
        model_runtime_loader: ctx.model_runtime_loader,
        model_artifact_resolver: ctx.model_artifact_resolver,
        model_config_loader: ctx.model_config_loader,
        promotion_store: ctx.promotion_store,
    })
    .await?;

    let staging_manifest = ctx.staging_dir.join(MANIFEST_FILENAME);
    let manifest = ctx
        .model_config_loader
        .load_manifest(&staging_manifest)
        .map_err(PromoteError::ManifestInvalid)?;
    let models_dir = PathBuf::from(MODELS_DIR);
    let artifacts = collect_manifest_artifacts(ctx.staging_dir, &models_dir, &manifest)?;
    let before_status = ctx.inference.model_source_status();

    let backup_dir = models_dir.join(format!(".promote-backup-{}", Uuid::new_v4()));
    let before_json = serde_json::to_value(&before_status).map_err(PromoteError::AuditDetailSerialize)?;
    let audit_detail = serde_json::json!({
        "manifest_name": &validation.manifest_name,
        "adapter_kind": &validation.adapter_kind,
        "manifest_sha256": &validation.manifest_sha256,
        "artifacts": &validation.artifacts,
        "before": before_json,
    })
    .to_string();
    let audit_actor = format!("{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX}@{}", ctx.actor_username);

    promote_files_atomically_with_required_audit(
        ctx.promotion_store,
        &PromoteFileSet {
            staging_manifest: staging_manifest.clone(),
            artifacts,
            target_manifest: models_dir.join(MANIFEST_FILENAME),
            backup_dir,
        },
        ctx.audit_repo,
        &audit_actor,
        &audit_detail,
    )
    .await?;
    log!(AuditLog::AuditEvent(audit_actor, AUDIT_ACTION_MODEL_SWAP.to_string(),));
    drop(guard);

    Ok(validation)
}

fn validate_manifest_basename(field: &str, value: &str) -> Result<(), PromoteError> {
    if value.is_empty() {
        return Err(PromoteError::ManifestInvalid(format!(
            "manifest field {field} is empty"
        )));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(PromoteError::ManifestInvalid(format!(
            "manifest field {field} must be a basename, not a path: {value:?}"
        )));
    }
    if value == "." || value == ".." || value.contains("..") {
        return Err(PromoteError::ManifestInvalid(format!(
            "manifest field {field} must not contain path-traversal segments: {value:?}"
        )));
    }
    if Path::new(value).is_absolute() {
        return Err(PromoteError::ManifestInvalid(format!(
            "manifest field {field} must be relative, not absolute: {value:?}"
        )));
    }
    if Path::new(value).file_name().and_then(|s| s.to_str()) != Some(value) {
        return Err(PromoteError::ManifestInvalid(format!(
            "manifest field {field} must be a plain basename: {value:?}"
        )));
    }
    Ok(())
}

fn collect_manifest_artifacts(
    staging_dir: &Path,
    models_dir: &Path,
    manifest: &ModelManifest,
) -> Result<Vec<PromoteArtifact>, PromoteError> {
    let mut seen = HashSet::new();
    let mut artifacts = Vec::new();
    for stage in &manifest.stages {
        push_artifact(
            &mut artifacts,
            &mut seen,
            staging_dir,
            models_dir,
            &format!("stages[{}].model_file", stage.id),
            &stage.model_file,
            "onnx",
        )?;
        for step in &stage.preprocessing {
            if let Some(sidecar) = preprocessing_sidecar(step) {
                push_artifact(
                    &mut artifacts,
                    &mut seen,
                    staging_dir,
                    models_dir,
                    &format!("stages[{}].preprocessing.sidecar", stage.id),
                    sidecar,
                    "sidecar",
                )?;
            }
        }
    }
    Ok(artifacts)
}

fn push_artifact(
    artifacts: &mut Vec<PromoteArtifact>,
    seen: &mut HashSet<String>,
    staging_dir: &Path,
    models_dir: &Path,
    field: &str,
    file: &str,
    kind: &str,
) -> Result<(), PromoteError> {
    validate_manifest_basename(field, file)?;
    if seen.insert(file.to_string()) {
        let backup_name = format!("artifact-{}-{file}", artifacts.len());
        artifacts.push(PromoteArtifact {
            file: file.to_string(),
            kind: kind.to_string(),
            staged: staging_dir.join(file),
            target: models_dir.join(file),
            backup_name,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ArtifactDigest {
    pub file: String,
    pub kind: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct ModelValidationReport {
    pub manifest_name: String,
    pub adapter_kind: String,
    pub manifest_sha256: String,
    pub artifacts: Vec<ArtifactDigest>,
}

pub struct PromoteFileSet {
    pub staging_manifest: PathBuf,
    pub artifacts: Vec<PromoteArtifact>,
    pub target_manifest: PathBuf,
    pub backup_dir: PathBuf,
}

pub struct PromoteArtifact {
    pub file: String,
    pub kind: String,
    pub staged: PathBuf,
    pub target: PathBuf,
    pub backup_name: String,
}

#[cfg(test)]
pub async fn promote_files_atomically(
    store: &dyn ModelPromotionStore,
    files: &PromoteFileSet,
) -> Result<(), PromoteError> {
    promote_files_with_backups(store, files).await?;
    cleanup_backup_dir(store, &files.backup_dir).await;
    Ok(())
}

async fn promote_files_atomically_with_required_audit(
    store: &dyn ModelPromotionStore,
    files: &PromoteFileSet,
    audit_repo: &dyn AuditRepo,
    audit_actor: &str,
    audit_detail: &str,
) -> Result<(), PromoteError> {
    audit_repo
        .insert_audit_log(audit_actor, AUDIT_ACTION_MODEL_SWAP, audit_detail)
        .await
        .map_err(PromoteError::AuditWrite)?;

    let backups = promote_files_with_backups(store, files).await?;
    cleanup_backup_dir(store, &files.backup_dir).await;
    drop(backups);
    Ok(())
}

async fn promote_files_with_backups(
    store: &dyn ModelPromotionStore,
    files: &PromoteFileSet,
) -> Result<PromoteBackups, PromoteError> {
    store
        .create_dir_all(&files.backup_dir)
        .await
        .map_err(|e| PromoteError::PromoteIo("create promote backup dir", e))?;

    let backups = PromoteBackups {
        manifest: backup_existing(store, &files.target_manifest, &files.backup_dir, "manifest.yaml").await?,
        artifacts: backup_existing_artifacts(store, files).await?,
    };

    let result = async {
        for artifact in &files.artifacts {
            move_file(
                store,
                &artifact.staged,
                &artifact.target,
                format!("rename {} into models/", artifact.file),
            )
            .await?;
        }
        move_file(
            store,
            &files.staging_manifest,
            &files.target_manifest,
            "rename manifest into models/",
        )
        .await
    }
    .await;

    match result {
        Ok(()) => Ok(backups),
        Err(err) => {
            rollback_promote(store, files, backups).await;
            cleanup_backup_dir(store, &files.backup_dir).await;
            Err(err)
        }
    }
}

struct PromoteBackups {
    manifest: Option<PathBuf>,
    artifacts: Vec<(PathBuf, Option<PathBuf>)>,
}

async fn backup_existing_artifacts(
    store: &dyn ModelPromotionStore,
    files: &PromoteFileSet,
) -> Result<Vec<(PathBuf, Option<PathBuf>)>, PromoteError> {
    let mut backups = Vec::with_capacity(files.artifacts.len());
    for artifact in &files.artifacts {
        let backup = backup_existing(store, &artifact.target, &files.backup_dir, &artifact.backup_name).await?;
        backups.push((artifact.target.clone(), backup));
    }
    Ok(backups)
}

async fn backup_existing(
    store: &dyn ModelPromotionStore,
    target: &Path,
    backup_dir: &Path,
    backup_name: &str,
) -> Result<Option<PathBuf>, PromoteError> {
    if !store
        .exists(target)
        .await
        .map_err(|e| PromoteError::PromoteIo(format!("check existing target {}", target.display()), e))?
    {
        return Ok(None);
    }
    let backup = backup_dir.join(backup_name);
    store
        .rename(target, &backup)
        .await
        .map_err(|e| PromoteError::PromoteIo(format!("backup existing target {}", target.display()), e))?;
    Ok(Some(backup))
}

async fn move_file(
    store: &dyn ModelPromotionStore,
    src: &Path,
    dst: &Path,
    op: impl Into<String>,
) -> Result<(), PromoteError> {
    store.rename(src, dst).await.map_err(|e| PromoteError::PromoteIo(op, e))
}

async fn rollback_promote(store: &dyn ModelPromotionStore, files: &PromoteFileSet, backups: PromoteBackups) {
    remove_if_exists(store, &files.target_manifest).await;
    for artifact in &files.artifacts {
        remove_if_exists(store, &artifact.target).await;
    }
    restore_backup(store, backups.manifest, &files.target_manifest).await;
    for (target, backup) in backups.artifacts {
        restore_backup(store, backup, &target).await;
    }
}

async fn remove_if_exists(store: &dyn ModelPromotionStore, path: &Path) {
    match store.exists(path).await {
        Ok(true) => {
            if let Err(err) = store.remove_file(path).await {
                log!(MLLog::ModelPromotionRollbackFailed(
                    path.display().to_string(),
                    err.to_string()
                ));
            }
        }
        Ok(false) => {}
        Err(err) => {
            log!(MLLog::ModelPromotionRollbackFailed(
                path.display().to_string(),
                format!("check exists: {err}")
            ));
        }
    }
}

async fn restore_backup(store: &dyn ModelPromotionStore, backup: Option<PathBuf>, target: &Path) {
    if let Some(backup) = backup
        && let Err(err) = store.rename(&backup, target).await
    {
        log!(MLLog::ModelPromotionRollbackFailed(
            target.display().to_string(),
            format!("restore backup {}: {err}", backup.display())
        ));
    }
}

async fn cleanup_backup_dir(store: &dyn ModelPromotionStore, backup_dir: &Path) {
    if let Err(err) = store.remove_dir_all(backup_dir).await {
        log!(MLLog::ModelPromotionBackupCleanupFailed(
            backup_dir.display().to_string(),
            err.to_string()
        ));
    }
}

traceable! {
    PromoteError {
        #[error("Model manifest is invalid: {err}")]
        ManifestInvalid => tracing::Level::ERROR,

        #[error("Model failed validation: {err}")]
        ValidationFailed => tracing::Level::ERROR,

        #[error("Staging IO failed during {operation}: {err}")]
        StagingIo { operation: String } => tracing::Level::ERROR,

        #[error("Model promotion IO failed during {operation}: {err}")]
        PromoteIo { operation: String } => tracing::Level::ERROR,

        #[error("Audit detail serialization failed: {err}")]
        AuditDetailSerialize => tracing::Level::ERROR,

        #[error("Required model-swap audit write failed: {err}")]
        AuditWrite => tracing::Level::ERROR,

        #[no_source]
        #[error("Another model promote is already in progress")]
        ConcurrentPromote => tracing::Level::WARN,

        #[no_source]
        #[error("Another model validation is already in progress")]
        ConcurrentValidation => tracing::Level::WARN,
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use uuid::Uuid;

    use super::*;
    use crate::adapter::model_promotion_store::FsModelPromotionStore;
    use crate::common::error::Error;
    use crate::common::error::database::DatabaseError;
    use crate::domain::common::audit::AuditLogEntry;

    struct FailingAuditRepo;

    #[async_trait::async_trait]
    impl AuditRepo for FailingAuditRepo {
        async fn insert_audit_log(&self, _actor: &str, _action: &str, _detail: &str) -> Result<(), Error> {
            Err(DatabaseError::QueryFailed("forced audit failure"))?
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

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("nguardia-model-promotion-{tag}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn validate_manifest_basename_accepts_plain_filenames() {
        assert!(validate_manifest_basename("field", "sidecar.json").is_ok());
        assert!(validate_manifest_basename("field", "classifier.onnx").is_ok());
    }

    #[test]
    fn validate_manifest_basename_rejects_path_values() {
        let err = validate_manifest_basename("field", "../upload.json").expect_err("path-like value should fail");
        assert!(err.to_string().contains("must be a basename"));
    }

    #[tokio::test]
    async fn required_audit_failure_prevents_file_promotion() {
        let tmp = scratch_dir("audit-rollback");
        let staging = tmp.join("staging");
        let models = tmp.join("models");
        let backup = models.join(".promote-backup-test");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&models).unwrap();

        let staging_manifest = staging.join(MANIFEST_FILENAME);
        let staged_onnx = staging.join("model.onnx");
        let target_manifest = models.join(MANIFEST_FILENAME);
        let target_onnx = models.join("model.onnx");

        fs::write(&staging_manifest, b"new manifest").unwrap();
        fs::write(&staged_onnx, b"new onnx").unwrap();
        fs::write(&target_manifest, b"old manifest").unwrap();
        fs::write(&target_onnx, b"old onnx").unwrap();

        let store = FsModelPromotionStore;
        let err = promote_files_atomically_with_required_audit(
            &store,
            &PromoteFileSet {
                staging_manifest: staging_manifest.clone(),
                artifacts: vec![PromoteArtifact {
                    file: "model.onnx".to_string(),
                    kind: "onnx".to_string(),
                    staged: staged_onnx.clone(),
                    target: target_onnx.clone(),
                    backup_name: "artifact-0-model.onnx".to_string(),
                }],
                target_manifest: target_manifest.clone(),
                backup_dir: backup.clone(),
            },
            &FailingAuditRepo,
            "security_admin@example",
            "{}",
        )
        .await
        .expect_err("required audit failure should fail promote");

        assert!(matches!(err, PromoteError::AuditWrite { .. }));
        assert_eq!(fs::read(&target_manifest).unwrap(), b"old manifest");
        assert_eq!(fs::read(&target_onnx).unwrap(), b"old onnx");
        assert!(staging_manifest.exists());
        assert!(staged_onnx.exists());
        assert!(!backup.exists());
        fs::remove_dir_all(&tmp).ok();
    }
}
