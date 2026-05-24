use std::fs as stdfs;
use std::io::ErrorKind;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use actix_multipart::Multipart;
use actix_web::{HttpResponse, Responder, Scope, web};
use arc_swap::ArcSwap;
use futures_util::TryStreamExt;
use macros::log;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::task;
use uuid::Uuid;
use zip::ZipArchive;

use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::inference::model_promotion::{PromoteError, PromoteGate, StagedModelPromotion, validate_and_promote};
use crate::core::inference::runner::Inference;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::PERMISSION_USERS_ADMIN;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::model_files::{MANIFEST_FILENAME, MODELS_DIR, STAGING_SUBDIR};
use crate::infrastructure::model_promotion_deps::ModelPromotionDeps;
use crate::interface::system::audit::AuditRepo;

const FIELD_BUNDLE: &str = "bundle";
const BUNDLE_FILENAME: &str = "model_bundle.zip";
#[cfg(test)]
const ONNX_SNIFF_BYTES: usize = 16;
const PROMOTE_REQUIRED_PERMISSION: &str = PERMISSION_USERS_ADMIN;

pub fn initialize() -> Scope {
    web::scope("/ml/models").route("/upload", web::post().to(upload))
}

async fn upload(
    app_config: web::Data<ArcSwap<AppConfig>>,
    inference: web::Data<Inference>,
    audit_repo: web::Data<dyn AuditRepo>,
    promote_lock: web::Data<PromoteGate>,
    promotion_deps: web::Data<ModelPromotionDeps>,
    claims: AuthClaims,
    payload: Multipart,
) -> impl Responder {
    if !claims.permissions.iter().any(|p| p == PROMOTE_REQUIRED_PERMISSION) {
        return structured_error_response(
            403,
            "permission_denied",
            "authorization",
            format!("model upload requires the {PROMOTE_REQUIRED_PERMISSION} permission"),
            "Sign in as an administrator and retry promotion.",
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
        Ok(s) => s,
        Err(e) => {
            cleanup_staging_dir(&staging_dir).await;
            return e.into_response();
        }
    };
    let outcome = validate_and_promote(&StagedModelPromotion {
        staging_dir: &staging_dir,
        inference: inference.get_ref(),
        audit_repo: audit_repo.get_ref(),
        promote_gate: promote_lock.get_ref(),
        validation_gate: promotion_deps.validation_gate.as_ref(),
        actor_username: &claims.username,
        batch_size,
        onnx_load_timeout,
        model_runtime_loader: promotion_deps.model_runtime_loader.as_ref(),
        model_artifact_resolver: promotion_deps.model_artifact_resolver.as_ref(),
        model_config_loader: promotion_deps.model_config_loader.as_ref(),
        promotion_store: promotion_deps.promotion_store.as_ref(),
    })
    .await;
    cleanup_staging_dir(&staging_dir).await;

    match outcome {
        Ok(report) => HttpResponse::Ok().json(serde_json::json!({
            "promoted": true,
            "staging_id": staging_id,
            "bundle_bytes": summary.bundle_bytes,
            "manifest_bytes": summary.manifest_bytes,
            "onnx_bytes": summary.onnx_bytes,
            "scaler_bytes": summary.scaler_bytes,
            "manifest_name": report.manifest_name,
            "adapter_kind": report.adapter_kind,
            "manifest_sha256": report.manifest_sha256,
            "artifacts": report.artifacts,
        })),
        Err(e) => promote_error_response(e),
    }
}

pub(crate) async fn cleanup_staging_dir(staging_dir: &Path) {
    if let Err(err) = fs::remove_dir_all(staging_dir).await {
        if err.kind() == ErrorKind::NotFound {
            return;
        }
        log!(MLLog::ModelUploadStagingCleanupFailed(
            staging_dir.display().to_string(),
            err.to_string()
        ));
    }
}

#[derive(Debug)]
pub(crate) struct UploadSummary {
    pub bundle_bytes: usize,
    pub manifest_bytes: usize,
    pub onnx_bytes: usize,
    pub scaler_bytes: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UploadCaps {
    pub bundle: usize,
    pub manifest: usize,
    pub onnx: usize,
    pub scaler: usize,
}

impl UploadCaps {
    pub(crate) fn from_config(config: &AppConfig) -> Self {
        Self {
            bundle: config
                .ml
                .model_upload
                .max_manifest_bytes
                .saturating_add(config.ml.model_upload.max_onnx_bytes)
                .saturating_add(config.ml.model_upload.max_scaler_bytes),
            manifest: config.ml.model_upload.max_manifest_bytes,
            onnx: config.ml.model_upload.max_onnx_bytes,
            scaler: config.ml.model_upload.max_scaler_bytes,
        }
    }
}

#[derive(Debug)]
pub(crate) enum UploadError {
    MissingField(&'static str),
    DuplicateField(&'static str),
    FilenameConflict(String),
    UnknownField(String),
    BundleTooLarge(usize),
    BundleNotZip,
    BundleEntryInvalid(String),
    BundleExtractionFailed(String),
    ManifestTooLarge(usize),
    OnnxTooLarge(usize),
    ScalerTooLarge(usize),
    StreamFailure(String),
    StagingSetupFailure(String),
}

impl UploadError {
    pub(crate) fn into_response(self) -> HttpResponse {
        let (status, code, category, message, hint) = match self {
            Self::MissingField(name) => (
                400,
                "missing_field",
                "transport",
                format!("missing required multipart field: {name}"),
                "Send the model bundle in the multipart field named 'bundle'.",
            ),
            Self::DuplicateField(name) => (
                400,
                "duplicate_field",
                "transport",
                format!("multipart field sent twice: {name}"),
                "Send exactly one bundle field.",
            ),
            Self::FilenameConflict(name) => (
                400,
                "filename_conflict",
                "bundle",
                format!("multipart filename conflicts with another upload file: {name}"),
                "Ensure every file in the bundle has a unique top-level basename.",
            ),
            Self::UnknownField(name) => (
                400,
                "unknown_field",
                "transport",
                format!("unexpected multipart field: {name}"),
                "Only the bundle field is accepted.",
            ),
            Self::BundleTooLarge(max_bytes) => (
                413,
                "bundle_too_large",
                "policy",
                format!("bundle exceeds {max_bytes} bytes"),
                "Reduce bundle size or raise the configured model upload limit.",
            ),
            Self::BundleNotZip => (
                400,
                "bundle_not_zip",
                "bundle",
                "bundle field does not look like a zip archive".to_string(),
                "Upload the trainer-exported model_bundle.zip file.",
            ),
            Self::BundleEntryInvalid(err) => (
                422,
                "bundle_entry_invalid",
                "bundle",
                format!("invalid bundle entry: {err}"),
                "Keep bundle files at the top level with safe basenames.",
            ),
            Self::BundleExtractionFailed(err) => (
                422,
                "bundle_extraction_failed",
                "bundle",
                format!("bundle extraction failed: {err}"),
                "Recreate the bundle and verify it contains manifest.yaml and ONNX artifacts.",
            ),
            Self::ManifestTooLarge(max_bytes) => (
                413,
                "manifest_too_large",
                "policy",
                format!("manifest exceeds {max_bytes} bytes"),
                "Reduce manifest size or raise the configured manifest upload limit.",
            ),
            Self::OnnxTooLarge(max_bytes) => (
                413,
                "onnx_too_large",
                "policy",
                format!("onnx exceeds {max_bytes} bytes"),
                "Reduce model size or raise the configured ONNX upload limit.",
            ),
            Self::ScalerTooLarge(max_bytes) => (
                413,
                "sidecar_too_large",
                "policy",
                format!("scaler exceeds {max_bytes} bytes"),
                "Reduce sidecar size or raise the configured sidecar upload limit.",
            ),
            Self::StreamFailure(err) => (
                400,
                "upload_stream_failure",
                "transport",
                format!("upload stream error: {err}"),
                "Retry the upload with a complete bundle.",
            ),
            Self::StagingSetupFailure(err) => (
                500,
                "staging_setup_failure",
                "storage",
                format!("staging directory error: {err}"),
                "Check server storage permissions and available space.",
            ),
        };
        structured_error_response(status, code, category, message, hint)
    }
}

pub(crate) fn structured_error_response(
    status: u16,
    code: &str,
    category: &str,
    message: impl Into<String>,
    hint: &str,
) -> HttpResponse {
    let message = message.into();
    let body = serde_json::json!({
        "code": code,
        "category": category,
        "message": &message,
        "hint": hint,
        "error": &message,
    });
    match status {
        400 => HttpResponse::BadRequest().json(body),
        403 => HttpResponse::Forbidden().json(body),
        409 => HttpResponse::Conflict().json(body),
        413 => HttpResponse::PayloadTooLarge().json(body),
        422 => HttpResponse::UnprocessableEntity().json(body),
        _ => HttpResponse::InternalServerError().json(body),
    }
}

pub(crate) async fn ingest_multipart(
    mut payload: Multipart,
    staging_dir: &Path,
    caps: UploadCaps,
) -> Result<UploadSummary, UploadError> {
    fs::create_dir_all(staging_dir)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;

    let mut bundle_summary: Option<usize> = None;

    while let Some(mut field) = payload
        .try_next()
        .await
        .map_err(|e| UploadError::StreamFailure(e.to_string()))?
    {
        let field_name = field
            .content_disposition()
            .and_then(|cd| cd.get_name())
            .unwrap_or("")
            .to_string();
        match field_name.as_str() {
            FIELD_BUNDLE => {
                if bundle_summary.is_some() {
                    return Err(UploadError::DuplicateField(FIELD_BUNDLE));
                }
                let _uploaded_name = field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .map(sanitize_filename)
                    .unwrap_or_else(|| BUNDLE_FILENAME.to_string());
                let bundle_filename = BUNDLE_FILENAME.to_string();
                let dest = staging_dir.join(&bundle_filename);
                let written = stream_field_to_file(&mut field, &dest, caps.bundle).await?;
                bundle_summary = Some(written);
            }
            other => {
                return Err(UploadError::UnknownField(other.to_string()));
            }
        }
    }

    let bundle_bytes = bundle_summary.ok_or(UploadError::MissingField(FIELD_BUNDLE))?;
    let bundle_path = staging_dir.join(BUNDLE_FILENAME);
    let extracted = extract_bundle_zip_blocking(bundle_path, staging_dir.to_path_buf(), caps).await?;

    Ok(UploadSummary {
        bundle_bytes,
        manifest_bytes: extracted.manifest_bytes,
        onnx_bytes: extracted.onnx_bytes,
        scaler_bytes: extracted.scaler_bytes,
    })
}

async fn stream_field_to_file(
    field: &mut actix_multipart::Field,
    dest: &Path,
    max_bytes: usize,
) -> Result<usize, UploadError> {
    let mut file = fs::File::create(dest)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;
    let mut total = 0usize;
    let mut sniffed = false;

    while let Some(chunk) = field
        .try_next()
        .await
        .map_err(|e| UploadError::StreamFailure(e.to_string()))?
    {
        if !sniffed {
            if !looks_like_zip(&chunk) {
                return Err(UploadError::BundleNotZip);
            }
            sniffed = true;
        }
        total = total.saturating_add(chunk.len());
        if total > max_bytes {
            return Err(UploadError::BundleTooLarge(max_bytes));
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| UploadError::StreamFailure(e.to_string()))?;
    }
    file.flush()
        .await
        .map_err(|e| UploadError::StreamFailure(e.to_string()))?;
    Ok(total)
}

async fn extract_bundle_zip_blocking(
    bundle_path: PathBuf,
    staging_dir: PathBuf,
    caps: UploadCaps,
) -> Result<BundleExtractionSummary, UploadError> {
    task::spawn_blocking(move || extract_bundle_zip(&bundle_path, &staging_dir, caps))
        .await
        .map_err(|e| UploadError::BundleExtractionFailed(format!("extract join failed: {e}")))?
}

fn reserve_upload_filename(used: &mut Vec<String>, filename: &str) -> Result<(), UploadError> {
    if used.iter().any(|existing| existing == filename) {
        return Err(UploadError::FilenameConflict(filename.to_string()));
    }
    used.push(filename.to_string());
    Ok(())
}

#[derive(Debug)]
struct BundleExtractionSummary {
    manifest_bytes: usize,
    onnx_bytes: usize,
    scaler_bytes: Option<usize>,
}

fn extract_bundle_zip(
    bundle_path: &Path,
    staging_dir: &Path,
    caps: UploadCaps,
) -> Result<BundleExtractionSummary, UploadError> {
    let file = stdfs::File::open(bundle_path).map_err(|e| UploadError::BundleExtractionFailed(e.to_string()))?;
    let mut archive = ZipArchive::new(file).map_err(|e| UploadError::BundleExtractionFailed(e.to_string()))?;

    let mut seen_files: Vec<String> = Vec::with_capacity(archive.len());
    let mut manifest_bytes = None;
    let mut onnx_bytes = 0usize;
    let mut scaler_bytes = None;
    let mut total_uncompressed = 0usize;

    for idx in 0..archive.len() {
        let entry = archive
            .by_index(idx)
            .map_err(|e| UploadError::BundleExtractionFailed(e.to_string()))?;
        if entry.is_dir() {
            continue;
        }
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| UploadError::BundleEntryInvalid(entry.name().to_string()))?;
        if enclosed.components().count() != 1 {
            return Err(UploadError::BundleEntryInvalid(format!(
                "nested archive paths are not allowed: {}",
                enclosed.display()
            )));
        }
        let filename = enclosed
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| UploadError::BundleEntryInvalid(entry.name().to_string()))?;
        reserve_upload_filename(&mut seen_files, filename)?;

        let dest = staging_dir.join(filename);
        let mut out = stdfs::File::create(&dest).map_err(|e| UploadError::BundleExtractionFailed(e.to_string()))?;
        let max_for_file = match filename {
            MANIFEST_FILENAME => caps.manifest,
            _ if filename.ends_with(".onnx") => caps.onnx,
            _ if filename.ends_with(".json") => caps.scaler,
            _ => caps.bundle,
        };
        let copied = io::copy(&mut entry.take((max_for_file as u64).saturating_add(1)), &mut out)
            .map_err(|e| UploadError::BundleExtractionFailed(e.to_string()))?;
        let copied = usize::try_from(copied)
            .map_err(|_| UploadError::BundleExtractionFailed("copied size overflow".to_string()))?;
        if copied > max_for_file {
            return Err(match filename {
                MANIFEST_FILENAME => UploadError::ManifestTooLarge(caps.manifest),
                _ if filename.ends_with(".onnx") => UploadError::OnnxTooLarge(caps.onnx),
                _ if filename.ends_with(".json") => UploadError::ScalerTooLarge(caps.scaler),
                _ => UploadError::BundleExtractionFailed(format!("entry '{filename}' exceeds extraction cap")),
            });
        }
        total_uncompressed = total_uncompressed.saturating_add(copied);
        if total_uncompressed > caps.bundle {
            return Err(UploadError::BundleExtractionFailed(
                "bundle expands beyond configured upload limits".to_string(),
            ));
        }

        match filename {
            MANIFEST_FILENAME => {
                manifest_bytes = Some(copied);
            }
            _ if filename.ends_with(".onnx") => {
                onnx_bytes = onnx_bytes.saturating_add(copied);
            }
            _ if filename.ends_with(".json") => {
                scaler_bytes = Some(copied);
            }
            _ => {}
        }
    }

    let manifest_bytes = manifest_bytes
        .ok_or_else(|| UploadError::BundleExtractionFailed("manifest.yaml missing from bundle".to_string()))?;
    if onnx_bytes == 0 {
        return Err(UploadError::BundleExtractionFailed(
            "no onnx model files found in bundle".to_string(),
        ));
    }

    Ok(BundleExtractionSummary {
        manifest_bytes,
        onnx_bytes,
        scaler_bytes,
    })
}

pub fn sanitize_filename(raw: impl AsRef<str>) -> String {
    let raw = raw.as_ref();
    let trimmed = raw.rsplit(['/', '\\']).next().unwrap_or("model.onnx");
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "model.onnx".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
pub fn looks_like_onnx(first_chunk: &[u8]) -> bool {
    if first_chunk.is_empty() {
        return false;
    }

    const BLOCKED_MAGICS: &[&[u8]] = &[b"PK\x03\x04", b"\x89PNG", b"%PDF", b"\x7fELF"];
    for magic in BLOCKED_MAGICS {
        if first_chunk.starts_with(magic) {
            return false;
        }
    }
    let prefix = &first_chunk[..first_chunk.len().min(ONNX_SNIFF_BYTES)];
    if prefix.iter().all(|&b| b == 0) {
        return false;
    }
    let mostly_ascii = prefix.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count() >= prefix.len() - 1;
    if mostly_ascii {
        return false;
    }
    true
}

pub fn looks_like_zip(first_chunk: &[u8]) -> bool {
    first_chunk.starts_with(b"PK")
}

fn promote_error_response(error: PromoteError) -> HttpResponse {
    let (status, code, category, message, hint) = match error {
        PromoteError::ManifestInvalid { err } => (
            422,
            "manifest_invalid",
            "schema",
            format!("manifest invalid: {err}"),
            "Fix manifest.yaml and validate the bundle again.",
        ),
        PromoteError::ValidationFailed { err } => (
            422,
            "model_validation_failed",
            "runtime_contract",
            format!("model failed validation: {err}"),
            "Check manifest, sidecar, feature order, and ONNX runtime contract.",
        ),
        PromoteError::StagingIo { operation, err } => (
            500,
            "staging_io_failed",
            "storage",
            format!("staging io error during {operation}: {err}"),
            "Check server storage permissions and available space.",
        ),
        PromoteError::PromoteIo { operation, err } => (
            500,
            "promotion_io_failed",
            "storage",
            format!("promote io error during {operation}: {err}"),
            "Check server storage permissions and retry promotion.",
        ),
        PromoteError::AuditDetailSerialize { err } => (
            500,
            "audit_detail_serialize_failed",
            "audit",
            format!("audit detail serialization failed: {err}"),
            "Retry after checking server logs.",
        ),
        PromoteError::AuditWrite { err } => (
            500,
            "audit_write_failed",
            "audit",
            format!("required audit write failed: {err}"),
            "Promotion requires audit persistence; check database health.",
        ),
        PromoteError::ConcurrentPromote => (
            409,
            "concurrent_promote",
            "concurrency",
            "another model promote is already in progress".to_string(),
            "Wait for the current promotion to finish and retry.",
        ),
        PromoteError::ConcurrentValidation => (
            409,
            "concurrent_validation",
            "concurrency",
            "another model validation is already in progress".to_string(),
            "Wait for the current validation to finish and retry.",
        ),
    };
    structured_error_response(status, code, category, message, hint)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs as stdfs;
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use super::*;
    use crate::adapter::model_promotion_store::FsModelPromotionStore;
    use crate::core::inference::model_promotion::{PromoteArtifact, PromoteFileSet, promote_files_atomically};
    use crate::infrastructure::staging_cleanup::clean_staging_orphans;
    use crate::interface::detection::model_promotion_store::ModelPromotionStore;

    #[test]
    fn onnx_sniff_rejects_empty() {
        assert!(!looks_like_onnx(&[]));
    }

    #[test]
    fn onnx_sniff_rejects_zero_padded_prefix() {
        assert!(!looks_like_onnx(&[0u8; 32]));
    }

    #[test]
    fn onnx_sniff_rejects_plain_text() {
        assert!(!looks_like_onnx(b"name: wrong-file\nkind: yaml\n"));
        assert!(!looks_like_onnx(b"PK\x03\x04"));
    }

    #[test]
    fn onnx_sniff_accepts_varint_tag_prefix() {
        let buf = [0x08u8, 0x07, 0x12, 0x0a, 0x70, 0x79, 0x74, 0x6f, 0x72, 0x63, 0x68, 0x00];
        assert!(looks_like_onnx(&buf));
    }

    #[test]
    fn onnx_sniff_accepts_length_delimited_tag() {
        let buf = [0x0au8, 0x10, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert!(looks_like_onnx(&buf));
    }

    #[test]
    fn zip_sniff_accepts_local_file_header() {
        assert!(looks_like_zip(b"PK\x03\x04"));
        assert!(!looks_like_zip(b"name: not-a-zip"));
    }

    #[test]
    fn sanitize_filename_strips_directory_components() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("subdir/model.onnx"), "model.onnx");
        assert_eq!(sanitize_filename("/abs/path/classifier.onnx"), "classifier.onnx");
        assert_eq!(sanitize_filename(r"C:\fakepath\model.onnx"), "model.onnx");
    }

    #[test]
    fn sanitize_filename_rejects_degenerate_values() {
        assert_eq!(sanitize_filename(""), "model.onnx");
        assert_eq!(sanitize_filename("."), "model.onnx");
        assert_eq!(sanitize_filename(".."), "model.onnx");
    }

    #[test]
    fn reserve_upload_filename_rejects_manifest_collision() {
        let mut used = vec![MANIFEST_FILENAME.to_string()];

        let err = reserve_upload_filename(&mut used, MANIFEST_FILENAME).expect_err("manifest filename is reserved");

        assert!(matches!(err, UploadError::FilenameConflict(name) if name == MANIFEST_FILENAME));
    }

    #[test]
    fn reserve_upload_filename_rejects_duplicate_artifact_filenames() {
        let mut used = vec![MANIFEST_FILENAME.to_string()];

        reserve_upload_filename(&mut used, "model.onnx").expect("first artifact name is unique");
        let err = reserve_upload_filename(&mut used, "model.onnx").expect_err("artifact names must be unique");

        assert!(matches!(err, UploadError::FilenameConflict(name) if name == "model.onnx"));
    }

    #[test]
    fn orphan_cleanup_removes_every_dir_when_max_age_is_zero() {
        let tmp = env::temp_dir().join(format!("nguardia-staging-test-{}", Uuid::new_v4()));
        stdfs::create_dir_all(&tmp).unwrap();
        stdfs::create_dir_all(tmp.join("abandoned-1")).unwrap();
        stdfs::create_dir_all(tmp.join("abandoned-2")).unwrap();
        stdfs::write(tmp.join("sidecar.log"), b"noise").unwrap();

        let cleaned = clean_staging_orphans(&tmp, Duration::ZERO).unwrap();
        assert_eq!(cleaned, 2);
        assert!(!tmp.join("abandoned-1").exists());
        assert!(!tmp.join("abandoned-2").exists());
        assert!(tmp.join("sidecar.log").exists(), "non-directory entries must survive");

        stdfs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn orphan_cleanup_preserves_fresh_directories() {
        let tmp = env::temp_dir().join(format!("nguardia-staging-fresh-{}", Uuid::new_v4()));
        stdfs::create_dir_all(&tmp).unwrap();
        stdfs::create_dir_all(tmp.join("recent")).unwrap();

        let cleaned = clean_staging_orphans(&tmp, Duration::from_secs(3600)).unwrap();
        assert_eq!(cleaned, 0);
        assert!(tmp.join("recent").exists());

        stdfs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn orphan_cleanup_is_noop_when_staging_root_missing() {
        let missing = PathBuf::from("/nonexistent/staging/path/for/test");
        let cleaned = clean_staging_orphans(&missing, Duration::from_secs(60)).unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn sha256_file_produces_known_hex_digest() {
        let tmp = env::temp_dir().join(format!("nguardia-sha256-empty-{}", Uuid::new_v4()));
        stdfs::write(&tmp, b"").unwrap();
        let store = FsModelPromotionStore;
        let hex = store.sha256_file(&tmp).await.expect("hash empty file");
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        stdfs::remove_file(&tmp).ok();
    }

    #[tokio::test]
    async fn sha256_file_hex_matches_multi_chunk_content() {
        let tmp = env::temp_dir().join(format!("nguardia-sha256-bulk-{}", Uuid::new_v4()));
        let payload = "abc".repeat(30_000);
        stdfs::write(&tmp, payload.as_bytes()).unwrap();
        let store = FsModelPromotionStore;
        let hex = store.sha256_file(&tmp).await.expect("hash large file");
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let expected = hasher.finalize();
        let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected_hex);
        stdfs::remove_file(&tmp).ok();
    }

    #[test]
    fn promote_error_validation_failure_maps_to_422() {
        let resp = promote_error_response(PromoteError::ValidationFailed("shape mismatch"));
        assert_eq!(resp.status().as_u16(), 422);
    }

    #[test]
    fn promote_error_invalid_manifest_maps_to_422() {
        let resp = promote_error_response(PromoteError::ManifestInvalid("bad yaml"));
        assert_eq!(resp.status().as_u16(), 422);
    }

    #[test]
    fn promote_error_staging_io_maps_to_500() {
        let resp = promote_error_response(PromoteError::StagingIo("write upload", "disk full"));
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[test]
    fn promote_error_promote_io_maps_to_500() {
        let resp = promote_error_response(PromoteError::PromoteIo("rename active model", "rename failed"));
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[test]
    fn promote_error_audit_detail_serialize_maps_to_500() {
        let resp = promote_error_response(PromoteError::AuditDetailSerialize("status"));
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[tokio::test]
    async fn promote_files_rolls_back_active_files_when_sidecar_move_fails() {
        let tmp = env::temp_dir().join(format!("nguardia-promote-rollback-{}", Uuid::new_v4()));
        let staging = tmp.join("staging");
        let models = tmp.join("models");
        let backup = models.join(".promote-backup-test");
        fs::create_dir_all(&staging).await.unwrap();
        fs::create_dir_all(&models).await.unwrap();

        let staging_manifest = staging.join(MANIFEST_FILENAME);
        let staged_onnx = staging.join("model.onnx");
        let missing_sidecar = staging.join("missing-scaler.json");
        let target_manifest = models.join(MANIFEST_FILENAME);
        let target_onnx = models.join("model.onnx");
        let target_sidecar = models.join("scaler.json");

        fs::write(&staging_manifest, b"new manifest").await.unwrap();
        fs::write(&staged_onnx, b"new onnx").await.unwrap();
        fs::write(&target_manifest, b"old manifest").await.unwrap();
        fs::write(&target_onnx, b"old onnx").await.unwrap();
        fs::write(&target_sidecar, b"old sidecar").await.unwrap();

        let store = FsModelPromotionStore;
        let err = promote_files_atomically(
            &store,
            &PromoteFileSet {
                staging_manifest: staging_manifest.clone(),
                artifacts: vec![
                    PromoteArtifact {
                        file: "model.onnx".to_string(),
                        kind: "onnx".to_string(),
                        staged: staged_onnx,
                        target: target_onnx.clone(),
                        backup_name: "artifact-0-model.onnx".to_string(),
                    },
                    PromoteArtifact {
                        file: "scaler.json".to_string(),
                        kind: "sidecar".to_string(),
                        staged: missing_sidecar,
                        target: target_sidecar.clone(),
                        backup_name: "artifact-1-scaler.json".to_string(),
                    },
                ],
                target_manifest: target_manifest.clone(),
                backup_dir: backup,
            },
        )
        .await
        .expect_err("missing sidecar should fail promote");

        assert!(matches!(err, PromoteError::PromoteIo { .. }));
        assert_eq!(fs::read(&target_manifest).await.unwrap(), b"old manifest");
        assert_eq!(fs::read(&target_onnx).await.unwrap(), b"old onnx");
        assert_eq!(fs::read(&target_sidecar).await.unwrap(), b"old sidecar");

        fs::remove_dir_all(&tmp).await.ok();
    }

    #[test]
    fn upload_error_scaler_too_large_maps_to_413_and_echoes_cap() {
        let resp = UploadError::ScalerTooLarge(1234).into_response();
        assert_eq!(resp.status().as_u16(), 413);
    }

    #[test]
    fn upload_error_onnx_too_large_echoes_configured_cap_in_message() {
        let rendered = format!("{:?}", UploadError::OnnxTooLarge(7_000_000));
        assert!(
            rendered.contains("7000000"),
            "rendered error must include the cap: {rendered}"
        );
    }
}
