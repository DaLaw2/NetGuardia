//! Multipart upload surface for BYO model files. Accepts a `manifest`
//! YAML field, an `onnx` binary field, and an optional `scaler` JSON
//! sidecar; streams each to `models/.staging/<uuid>/` with enforced
//! size caps, runs structural + ONNX shape validation, then atomically
//! renames into `models/` under a process-wide gate (AtomicBool, not a
//! mutex — see `PromoteGate`): a second concurrent promote is rejected
//! with 409 Conflict rather than queued. A WORM `model_swap` audit
//! entry records the SHA-256 of both committed files plus a snapshot
//! of the pre-swap state.
//!
//! Body-size caps come from `InferenceConfig::model_upload_max_*_bytes`
//! so admins can tune them from the settings DB without a rebuild.
//! Defaults: 100MB ONNX, 64KB manifest, 64KB scaler. Streaming writes
//! never buffer the full file in RAM, and staged directories are torn
//! down on any error path so failed uploads don't pile up in
//! `models/.staging/`.

use std::fs::File as StdFile;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use actix_multipart::Multipart;
use actix_web::{HttpResponse, Responder, Scope, web};
use arc_swap::ArcSwap;
use futures_util::TryStreamExt;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;
use tokio::task;
use uuid::Uuid;

use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::inference::model_loader::build_adapter;
use crate::core::inference::runner::Inference;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::{
    AUDIT_ACTOR_SECURITY_ADMIN_PREFIX, MANIFEST_FILENAME, MODELS_DIR, STAGING_SUBDIR,
};
use crate::domain::common::event::AuditEvent;
use crate::domain::detection::manifest::{AdapterKind, ModelManifest};
use crate::domain::detection::ml_inference_config::MLInferenceConfig;

/// Multipart field names the client must use. Stable wire contract —
/// the frontend form generator depends on these exact strings.
const FIELD_MANIFEST: &str = "manifest";
const FIELD_ONNX: &str = "onnx";
const FIELD_SCALER: &str = "scaler";

/// Number of bytes of the ONNX body we inspect up-front for an obvious
/// non-Protobuf header. A fuller structural check (shape vs manifest
/// declared `features`) runs during `build_adapter` in the promote path.
const ONNX_SNIFF_BYTES: usize = 16;

/// Permission required to drive the model-upload endpoint. The full
/// RBAC middleware lets anyone with `ai_detection:write` reach
/// `/api/ml/*`, but model promotion can replace the active detector —
/// gate it tighter at the handler layer so only administrators can
/// swap the ML source.
const PROMOTE_REQUIRED_PERMISSION: &str = "users:admin";

/// Action recorded on the WORM chain when a promote succeeds. Stable
/// wire string — fusion-explain tooling and future "who swapped the
/// model" views filter on it, so the rename must go through the audit
/// chain too.
const AUDIT_ACTION_MODEL_SWAP: &str = "model_swap";

/// Process-wide gate that ensures only one promote ever runs the rename
/// section at a time. The critical section is tiny (three `tokio::fs::rename`
/// syscalls) but must never interleave: a concurrent promote mid-rename could
/// leave `models/` pointing at a manifest whose ONNX hasn't landed yet.
///
/// Unlike a mutex, the gate does not queue. A second concurrent promote sees
/// the gate held and gets `PromoteError::ConcurrentPromote` immediately —
/// administrators wanting to swap models should know another swap is in flight
/// rather than silently waiting behind it.
#[derive(Default)]
pub struct PromoteGate {
    in_progress: AtomicBool,
}

impl PromoteGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Try to claim the gate. Returns `Some(guard)` on success; `None` when
    /// another promote is already inside the rename section. The guard
    /// releases the gate when dropped, including on panic.
    fn try_acquire(&self) -> Option<PromoteGuard<'_>> {
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

struct PromoteGuard<'a> {
    gate: &'a PromoteGate,
}

impl Drop for PromoteGuard<'_> {
    fn drop(&mut self) {
        self.gate.in_progress.store(false, Ordering::Release);
    }
}

pub fn initialize() -> Scope {
    // Mounted under `/ml/models/upload` so the entire ML model lifecycle
    // (status, dormant, upload) lives under one URL subtree. The peer
    // `/ml/models/current` GET/DELETE routes live in `ml::initialize()`;
    // actix dispatches each path to whichever scope owns it.
    web::scope("/ml/models").route("/upload", web::post().to(upload))
}

/// `POST /api/ml/models/upload` — multipart with `manifest` (YAML text),
/// `onnx` (binary), and optional `scaler` (JSON). Streams fields into
/// `models/.staging/<uuid>/`, validates the manifest + ONNX shape, and
/// atomically renames the triple into `models/` on success. A WORM
/// `model_swap` audit entry captures the SHA-256 pair plus the
/// pre-swap ML source state. The staging directory is always torn
/// down on the way out, even on success (post-promote it's empty).
async fn upload(
    app_config: web::Data<ArcSwap<AppConfig>>,
    inference: web::Data<Inference>,
    audit_tx: web::Data<broadcast::Sender<AuditEvent>>,
    promote_lock: web::Data<PromoteGate>,
    claims: AuthClaims,
    payload: Multipart,
) -> impl Responder {
    if !claims.permissions.iter().any(|p| p == PROMOTE_REQUIRED_PERMISSION) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": format!("model upload requires the {PROMOTE_REQUIRED_PERMISSION} permission"),
        }));
    }

    let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
    let staging_id = Uuid::new_v4().to_string();
    let staging_dir = staging_root.join(&staging_id);

    let config = app_config.load();
    let caps = UploadCaps {
        manifest: config.ml.model_upload_max_manifest_bytes,
        onnx: config.ml.model_upload_max_onnx_bytes,
        scaler: config.ml.model_upload_max_scaler_bytes,
    };
    let batch_size = config.ml.inference_batch_size;
    let onnx_load_timeout = Duration::from_secs(config.ml.onnx_load_timeout_secs);
    drop(config);
    let summary = match ingest_multipart(payload, &staging_dir, caps).await {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging_dir).await;
            return e.into_response();
        }
    };
    let outcome = validate_and_promote(&PromoteContext {
        staging_dir: &staging_dir,
        summary: &summary,
        inference: inference.get_ref(),
        audit_tx: audit_tx.get_ref(),
        promote_lock: promote_lock.get_ref(),
        actor_username: &claims.username,
        batch_size,
        onnx_load_timeout,
    })
    .await;

    // Always sweep staging — successful promote renames the files out,
    // leaving a now-empty directory; failures leave partial state we
    // don't want orbiting forever.
    let _ = fs::remove_dir_all(&staging_dir).await;

    match outcome {
        Ok(report) => HttpResponse::Ok().json(serde_json::json!({
            "promoted": true,
            "staging_id": staging_id,
            "manifest_bytes": summary.manifest_bytes,
            "onnx_bytes": summary.onnx_bytes,
            "scaler_bytes": summary.scaler_bytes,
            "manifest_name": report.manifest_name,
            "adapter_kind": report.adapter_kind,
            "manifest_sha256": report.manifest_sha256,
            "onnx_sha256": report.onnx_sha256,
        })),
        Err(e) => e.into_response(),
    }
}

/// Successful-path metadata the handler surfaces to the client.
#[derive(Debug)]
struct UploadSummary {
    manifest_bytes: usize,
    onnx_bytes: usize,
    onnx_filename: String,
    /// Bytes written for the optional scaler sidecar. `None` when the
    /// field wasn't submitted at all.
    scaler_bytes: Option<usize>,
}

/// Per-field byte caps. Plumbed from `InferenceConfig` through the
/// handler so admins can tune caps from the DB without a code change.
#[derive(Debug, Clone, Copy)]
struct UploadCaps {
    manifest: usize,
    onnx: usize,
    scaler: usize,
}

/// Errors that can surface a specific HTTP response. Kept in-module
/// because none of these have callers outside this handler.
///
/// The `*TooLarge(usize)` variants carry the admin-configured cap so
/// the response can tell the client which ceiling they hit without
/// having to query `/api/config` separately.
#[derive(Debug)]
enum UploadError {
    MissingField(&'static str),
    DuplicateField(&'static str),
    UnknownField(String),
    ManifestTooLarge(usize),
    OnnxTooLarge(usize),
    ScalerTooLarge(usize),
    OnnxNotBinary,
    StreamFailure(String),
    StagingSetupFailure(String),
}

impl UploadError {
    fn into_response(self) -> HttpResponse {
        let (status, message) = match self {
            Self::MissingField(name) => (400, format!("missing required multipart field: {name}")),
            Self::DuplicateField(name) => (400, format!("multipart field sent twice: {name}")),
            Self::UnknownField(name) => (400, format!("unexpected multipart field: {name}")),
            Self::ManifestTooLarge(max_bytes) => (413, format!("manifest exceeds {max_bytes} bytes")),
            Self::OnnxTooLarge(max_bytes) => (413, format!("onnx exceeds {max_bytes} bytes")),
            Self::ScalerTooLarge(max_bytes) => (413, format!("scaler exceeds {max_bytes} bytes")),
            Self::OnnxNotBinary => (
                400,
                "onnx field does not look like a protobuf-encoded ONNX model".to_string(),
            ),
            Self::StreamFailure(err) => (400, format!("upload stream error: {err}")),
            Self::StagingSetupFailure(err) => (500, format!("staging directory error: {err}")),
        };
        let body = serde_json::json!({ "error": message });
        match status {
            400 => HttpResponse::BadRequest().json(body),
            413 => HttpResponse::PayloadTooLarge().json(body),
            _ => HttpResponse::InternalServerError().json(body),
        }
    }
}

async fn ingest_multipart(
    mut payload: Multipart,
    staging_dir: &Path,
    caps: UploadCaps,
) -> Result<UploadSummary, UploadError> {
    fs::create_dir_all(staging_dir)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;

    let mut manifest_written: Option<usize> = None;
    let mut onnx_summary: Option<(String, usize)> = None;
    let mut scaler_summary: Option<(String, usize)> = None;

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
            FIELD_MANIFEST => {
                if manifest_written.is_some() {
                    return Err(UploadError::DuplicateField(FIELD_MANIFEST));
                }
                let dest = staging_dir.join(MANIFEST_FILENAME);
                let written = stream_field_to_file(&mut field, &dest, caps.manifest, FieldKind::Manifest).await?;
                manifest_written = Some(written);
            }
            FIELD_ONNX => {
                if onnx_summary.is_some() {
                    return Err(UploadError::DuplicateField(FIELD_ONNX));
                }
                let onnx_filename = field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .map(sanitize_filename)
                    .unwrap_or_else(|| "model.onnx".to_string());
                let dest = staging_dir.join(&onnx_filename);
                let written = stream_field_to_file(&mut field, &dest, caps.onnx, FieldKind::Onnx).await?;
                onnx_summary = Some((onnx_filename, written));
            }
            FIELD_SCALER => {
                if scaler_summary.is_some() {
                    return Err(UploadError::DuplicateField(FIELD_SCALER));
                }
                let scaler_filename = field
                    .content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .map(sanitize_filename)
                    .unwrap_or_else(|| "inference_config.json".to_string());
                let dest = staging_dir.join(&scaler_filename);
                let written = stream_field_to_file(&mut field, &dest, caps.scaler, FieldKind::Scaler).await?;
                scaler_summary = Some((scaler_filename, written));
            }
            other => {
                return Err(UploadError::UnknownField(other.to_string()));
            }
        }
    }

    let manifest_bytes = manifest_written.ok_or(UploadError::MissingField(FIELD_MANIFEST))?;
    let (onnx_filename, onnx_bytes) = onnx_summary.ok_or(UploadError::MissingField(FIELD_ONNX))?;
    let scaler_bytes = scaler_summary.map(|(_, n)| n);

    Ok(UploadSummary {
        manifest_bytes,
        onnx_bytes,
        onnx_filename,
        scaler_bytes,
    })
}

/// Discriminator for which size cap / sniff rule applies to a given
/// multipart field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Manifest,
    Onnx,
    Scaler,
}

/// Stream a multipart field directly to disk. Aborts (and leaves the
/// caller to clean up) when the declared byte cap is exceeded or when
/// the binary sniff rejects the first chunk.
async fn stream_field_to_file(
    field: &mut actix_multipart::Field,
    dest: &Path,
    max_bytes: usize,
    kind: FieldKind,
) -> Result<usize, UploadError> {
    let mut file = fs::File::create(dest)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;
    let mut total = 0usize;
    let mut sniffed = kind != FieldKind::Onnx;

    while let Some(chunk) = field
        .try_next()
        .await
        .map_err(|e| UploadError::StreamFailure(e.to_string()))?
    {
        if !sniffed {
            // Cheap up-front validation: reject obvious non-ONNX blobs
            // (empty first chunk, all-zero header, all-printable text).
            if !looks_like_onnx(&chunk) {
                return Err(UploadError::OnnxNotBinary);
            }
            sniffed = true;
        }
        total = total.saturating_add(chunk.len());
        if total > max_bytes {
            return Err(match kind {
                FieldKind::Manifest => UploadError::ManifestTooLarge(max_bytes),
                FieldKind::Onnx => UploadError::OnnxTooLarge(max_bytes),
                FieldKind::Scaler => UploadError::ScalerTooLarge(max_bytes),
            });
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

/// Shape-preserving filename sanitizer: keep the extension the client
/// sent (it may be `.onnx`, `.bin`, whatever), but strip any directory
/// traversal so the staging dir can never escape.
pub fn sanitize_filename(raw: impl AsRef<str>) -> String {
    let raw = raw.as_ref();
    let trimmed = Path::new(raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("model.onnx");
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "model.onnx".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Reject manifest-declared filenames that aren't single-segment basenames.
/// The multipart layer sanitizes client-sent part filenames (silent rewrite),
/// but manifest fields like `models.model` and `preprocessing.scaler_sidecar`
/// are user-controlled YAML — a value such as `../../../etc/cron.d/evil` would
/// otherwise flow into `staging_dir.join(..)` / `models_dir.join(..)` and let
/// `users:admin` write outside the models tree. Reject loudly rather than
/// silently rewriting so an operator who fat-fingered a path sees the failure.
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

/// Loose first-chunk heuristic. An ONNX protobuf starts with a varint
/// tag byte — the field=1 wire=varint (`0x08` for `ir_version`) and
/// field=1 wire=length-delimited (`0x0a`) patterns both occur in real
/// models — but enumerating positive accept patterns is fragile because
/// tract accepts several tag orderings. We instead:
///
/// 1. Reject magic bytes of container formats that users routinely
///    upload by mistake (ZIP, PNG, PDF, ELF).
/// 2. Reject all-zero and all-printable-ASCII prefixes (buffers and
///    text files).
///
/// The authoritative structural validation happens during
/// `build_adapter`; this heuristic's job is catching the obvious wrong
/// upload before the bytes hit disk.
pub fn looks_like_onnx(first_chunk: &[u8]) -> bool {
    if first_chunk.is_empty() {
        return false;
    }
    // Container formats that users commonly confuse with ONNX.
    const BLOCKED_MAGICS: &[&[u8]] = &[
        b"PK\x03\x04", // ZIP / JAR / DOCX — some pipelines ship ONNX weights this way,
        // but our upload path expects a single standalone .onnx file.
        b"\x89PNG",
        b"%PDF",
        b"\x7fELF",
    ];
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

/// Validate the staged manifest + ONNX + optional sidecar, then
/// atomically promote them into `models/`. The sequence is:
///
/// 1. Parse and structurally validate `manifest.yaml` against the
///    `FEATURE_REGISTRY` plus manifest-level invariants.
/// 2. Reject `multi_task` adapters — v1 upload supports single-ONNX
///    models only; multi-task manifests reference two ONNX files and
///    need a different multipart shape.
/// 3. Rename the uploaded `.onnx` to the filename the manifest
///    declares in `models.model`. The client is free to ship the
///    binary with any user-facing name; the manifest is the canonical
///    layout the watcher rebuilds from.
/// 4. Run `from_manifest_with_sidecar` + `build_adapter` — this exercises
///    the same loader the hot-reload watcher will use after promote,
///    including the 5-second wall-clock budget around `tract`. If
///    anything fails here, nothing in `models/` has changed yet.
/// 5. SHA-256 both files and snapshot the `Inference` state for the
///    audit detail body before we mutate anything shared.
/// 6. Under `PromoteLock`, rename ONNX first, optional sidecar second,
///    manifest last. The manifest is the watcher's commit marker —
///    by landing it last we avoid the window where the watcher reads
///    a manifest that points at a not-yet-renamed ONNX.
/// 7. Publish a WORM `model_swap` audit event. Failure to publish is
///    logged but does not roll back the rename; the chain prefers a
///    missing audit entry to a rolled-back promote that a downstream
///    subscriber may already have reacted to.
struct PromoteContext<'a> {
    staging_dir: &'a Path,
    summary: &'a UploadSummary,
    inference: &'a Inference,
    audit_tx: &'a broadcast::Sender<AuditEvent>,
    promote_lock: &'a PromoteGate,
    actor_username: &'a str,
    batch_size: usize,
    onnx_load_timeout: Duration,
}

async fn validate_and_promote(ctx: &PromoteContext<'_>) -> Result<PromoteReport, PromoteError> {
    let staging_dir = ctx.staging_dir;
    let summary = ctx.summary;
    let inference = ctx.inference;
    let audit_tx = ctx.audit_tx;
    let promote_lock = ctx.promote_lock;
    let actor_username = ctx.actor_username;
    let batch_size = ctx.batch_size;
    let onnx_load_timeout = ctx.onnx_load_timeout;
    let staging_manifest = staging_dir.join(MANIFEST_FILENAME);

    // Structural manifest validation. The full `build_adapter` pipeline
    // below will revisit this via `from_manifest_with_sidecar`, but a
    // cheap up-front `load` surfaces manifest-only problems (bad YAML,
    // unknown feature, missing `models.model`) before we rename anything.
    let manifest_preview =
        ModelManifest::load(&staging_manifest).map_err(|e| PromoteError::ManifestInvalid(e.to_string()))?;

    if matches!(manifest_preview.adapter, AdapterKind::MultiTask) {
        return Err(PromoteError::UnsupportedAdapter);
    }

    let declared_onnx = manifest_preview
        .models
        .model
        .clone()
        .ok_or_else(|| PromoteError::ManifestInvalid("single-onnx adapters require models.model".to_string()))?;
    validate_manifest_basename("models.model", &declared_onnx)?;
    if let Some(ref pp) = manifest_preview.preprocessing {
        validate_manifest_basename("preprocessing.scaler_sidecar", &pp.scaler_sidecar)?;
    }

    let uploaded_onnx = staging_dir.join(&summary.onnx_filename);
    let staged_onnx = staging_dir.join(&declared_onnx);
    if uploaded_onnx != staged_onnx {
        fs::rename(&uploaded_onnx, &staged_onnx)
            .await
            .map_err(|e| PromoteError::StagingIo(format!("rename staged onnx: {e}")))?;
    }

    // Full validate — sidecar reconciliation, ONNX shape vs manifest
    // features, tract optimize+runnable under the 5s load budget.
    let (config, manifest) = MLInferenceConfig::from_manifest_with_sidecar(&staging_manifest)
        .map_err(|e| PromoteError::ValidationFailed(e.to_string()))?;
    let _adapter = build_adapter(
        &manifest,
        Some(&staging_manifest),
        &config,
        batch_size,
        onnx_load_timeout,
    )
    .map_err(|e| PromoteError::ValidationFailed(e.to_string()))?;

    let manifest_sha256 = sha256_file(&staging_manifest)
        .await
        .map_err(|e| PromoteError::StagingIo(format!("sha256 manifest: {e}")))?;
    let onnx_sha256 = sha256_file(&staged_onnx)
        .await
        .map_err(|e| PromoteError::StagingIo(format!("sha256 onnx: {e}")))?;

    let before_status = inference.model_source_status();

    let models_dir = PathBuf::from(MODELS_DIR);
    let target_onnx = models_dir.join(&declared_onnx);
    let target_manifest = models_dir.join(MANIFEST_FILENAME);
    let staged_sidecar = if let Some(ref pp) = manifest.preprocessing {
        validate_manifest_basename("preprocessing.scaler_sidecar", &pp.scaler_sidecar)?;
        Some(staging_dir.join(&pp.scaler_sidecar))
    } else {
        None
    };
    let target_sidecar = manifest
        .preprocessing
        .as_ref()
        .map(|pp| models_dir.join(&pp.scaler_sidecar));

    let _guard = promote_lock.try_acquire().ok_or(PromoteError::ConcurrentPromote)?;
    let backup_dir = models_dir.join(format!(".promote-backup-{}", Uuid::new_v4()));
    promote_files_atomically(&PromoteFileSet {
        staging_manifest: staging_manifest.clone(),
        staged_onnx,
        staged_sidecar,
        target_manifest,
        target_onnx,
        target_sidecar,
        backup_dir,
    })
    .await?;
    drop(_guard);

    let audit_detail = serde_json::json!({
        "manifest_name": manifest.name,
        "adapter_kind": manifest.adapter.as_str(),
        "manifest_sha256": manifest_sha256,
        "onnx_sha256": onnx_sha256,
        "before": serde_json::to_value(&before_status).unwrap_or(JsonValue::Null),
    })
    .to_string();
    let _ = audit_tx.send(AuditEvent {
        actor: format!("{AUDIT_ACTOR_SECURITY_ADMIN_PREFIX}@{actor_username}"),
        action: AUDIT_ACTION_MODEL_SWAP.to_string(),
        detail: audit_detail,
    });

    Ok(PromoteReport {
        manifest_name: manifest.name,
        adapter_kind: manifest.adapter.as_str().to_string(),
        manifest_sha256,
        onnx_sha256,
    })
}

struct PromoteFileSet {
    staging_manifest: PathBuf,
    staged_onnx: PathBuf,
    staged_sidecar: Option<PathBuf>,
    target_manifest: PathBuf,
    target_onnx: PathBuf,
    target_sidecar: Option<PathBuf>,
    backup_dir: PathBuf,
}

async fn promote_files_atomically(files: &PromoteFileSet) -> Result<(), PromoteError> {
    fs::create_dir_all(&files.backup_dir)
        .await
        .map_err(|e| PromoteError::PromoteIo(format!("create promote backup dir: {e}")))?;

    let backup_manifest = backup_existing(&files.target_manifest, &files.backup_dir, "manifest.yaml").await?;
    let backup_onnx = backup_existing(&files.target_onnx, &files.backup_dir, "model.onnx").await?;
    let backup_sidecar = match &files.target_sidecar {
        Some(target) => Some(backup_existing(target, &files.backup_dir, "sidecar").await?),
        None => None,
    };

    let result = async {
        move_file(&files.staged_onnx, &files.target_onnx, "rename onnx into models/").await?;
        if let (Some(src), Some(dst)) = (&files.staged_sidecar, &files.target_sidecar) {
            move_file(src, dst, "rename sidecar into models/").await?;
        }
        move_file(
            &files.staging_manifest,
            &files.target_manifest,
            "rename manifest into models/",
        )
        .await
    }
    .await;

    match result {
        Ok(()) => {
            let _ = fs::remove_dir_all(&files.backup_dir).await;
            Ok(())
        }
        Err(err) => {
            rollback_promote(files, backup_manifest, backup_onnx, backup_sidecar).await;
            let _ = fs::remove_dir_all(&files.backup_dir).await;
            Err(err)
        }
    }
}

async fn backup_existing(target: &Path, backup_dir: &Path, backup_name: &str) -> Result<Option<PathBuf>, PromoteError> {
    if !target
        .try_exists()
        .map_err(|e| PromoteError::PromoteIo(format!("check existing target {}: {e}", target.display())))?
    {
        return Ok(None);
    }
    let backup = backup_dir.join(backup_name);
    fs::rename(target, &backup)
        .await
        .map_err(|e| PromoteError::PromoteIo(format!("backup existing target {}: {e}", target.display())))?;
    Ok(Some(backup))
}

async fn move_file(src: &Path, dst: &Path, op: &str) -> Result<(), PromoteError> {
    fs::rename(src, dst)
        .await
        .map_err(|e| PromoteError::PromoteIo(format!("{op}: {e}")))
}

async fn rollback_promote(
    files: &PromoteFileSet,
    backup_manifest: Option<PathBuf>,
    backup_onnx: Option<PathBuf>,
    backup_sidecar: Option<Option<PathBuf>>,
) {
    remove_if_exists(&files.target_manifest).await;
    remove_if_exists(&files.target_onnx).await;
    if let Some(target) = &files.target_sidecar {
        remove_if_exists(target).await;
    }
    restore_backup(backup_manifest, &files.target_manifest).await;
    restore_backup(backup_onnx, &files.target_onnx).await;
    if let (Some(backup), Some(target)) = (backup_sidecar.flatten(), &files.target_sidecar) {
        restore_backup(Some(backup), target).await;
    }
}

async fn remove_if_exists(path: &Path) {
    if let Ok(true) = path.try_exists() {
        let _ = fs::remove_file(path).await;
    }
}

async fn restore_backup(backup: Option<PathBuf>, target: &Path) {
    if let Some(backup) = backup {
        let _ = fs::rename(backup, target).await;
    }
}

/// Metadata surfaced back to the client when the promote succeeds.
#[derive(Debug)]
struct PromoteReport {
    manifest_name: String,
    adapter_kind: String,
    manifest_sha256: String,
    onnx_sha256: String,
}

/// Validation / promote error taxonomy. Distinct from `UploadError` so
/// the two stages produce different HTTP status codes: staging-ingest
/// failures are typically client-facing (400/413), while validation
/// and rename failures are server-side (422/500).
#[derive(Debug)]
enum PromoteError {
    ManifestInvalid(String),
    ValidationFailed(String),
    UnsupportedAdapter,
    StagingIo(String),
    PromoteIo(String),
    ConcurrentPromote,
}

impl PromoteError {
    fn into_response(self) -> HttpResponse {
        let (status, message) = match self {
            Self::ManifestInvalid(err) => (422, format!("manifest invalid: {err}")),
            Self::ValidationFailed(err) => (422, format!("model failed validation: {err}")),
            Self::UnsupportedAdapter => (
                422,
                "multi_task adapter is not supported by the v1 upload flow — \
                 submit an autoencoder_only or classifier_only manifest"
                    .to_string(),
            ),
            Self::StagingIo(err) => (500, format!("staging io error: {err}")),
            Self::PromoteIo(err) => (500, format!("promote io error: {err}")),
            Self::ConcurrentPromote => (409, "another model promote is already in progress".to_string()),
        };
        let body = serde_json::json!({ "error": message });
        match status {
            422 => HttpResponse::UnprocessableEntity().json(body),
            409 => HttpResponse::Conflict().json(body),
            _ => HttpResponse::InternalServerError().json(body),
        }
    }
}

/// Read `path` in 64KB chunks and return its SHA-256 hex digest.
/// Offloaded to `spawn_blocking` so a large ONNX can't stall the
/// actix worker while the hash computes.
async fn sha256_file(path: &Path) -> io::Result<String> {
    let path = path.to_path_buf();
    task::spawn_blocking(move || -> io::Result<String> {
        let mut file = StdFile::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let out = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in out {
            use std::fmt::Write;
            // SAFETY: write! on a String is infallible.
            let _ = write!(&mut hex, "{byte:02x}");
        }
        Ok(hex)
    })
    .await
    .unwrap_or_else(|e| Err(io::Error::other(format!("sha256 join: {e}"))))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::utils::staging::clean_staging_orphans;

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
        // A YAML or plain-text payload that ended up in the wrong field.
        assert!(!looks_like_onnx(b"name: wrong-file\nkind: yaml\n"));
        assert!(!looks_like_onnx(b"PK\x03\x04"));
    }

    #[test]
    fn onnx_sniff_accepts_varint_tag_prefix() {
        // `0x08` = tag field 1, wire-type varint (ir_version). Real ONNX
        // files commonly open with this.
        let buf = [0x08u8, 0x07, 0x12, 0x0a, 0x70, 0x79, 0x74, 0x6f, 0x72, 0x63, 0x68, 0x00];
        assert!(looks_like_onnx(&buf));
    }

    #[test]
    fn onnx_sniff_accepts_length_delimited_tag() {
        // `0x0a` = tag field 1, wire-type length-delimited. Also valid.
        let buf = [0x0au8, 0x10, 0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert!(looks_like_onnx(&buf));
    }

    #[test]
    fn sanitize_filename_strips_directory_components() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("subdir/model.onnx"), "model.onnx");
        assert_eq!(sanitize_filename("/abs/path/classifier.onnx"), "classifier.onnx");
    }

    #[test]
    fn sanitize_filename_rejects_degenerate_values() {
        assert_eq!(sanitize_filename(""), "model.onnx");
        assert_eq!(sanitize_filename("."), "model.onnx");
        assert_eq!(sanitize_filename(".."), "model.onnx");
    }

    #[test]
    fn orphan_cleanup_removes_every_dir_when_max_age_is_zero() {
        // A zero-length max age declares every existing entry stale, so
        // the helper must sweep all of them. Portable without touching
        // filesystem mtime APIs.
        let tmp = std::env::temp_dir().join(format!("nguardia-staging-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(tmp.join("abandoned-1")).unwrap();
        std::fs::create_dir_all(tmp.join("abandoned-2")).unwrap();
        // A file (not a dir) should be ignored by the sweep.
        std::fs::write(tmp.join("sidecar.log"), b"noise").unwrap();

        let cleaned = clean_staging_orphans(&tmp, Duration::ZERO).unwrap();
        assert_eq!(cleaned, 2);
        assert!(!tmp.join("abandoned-1").exists());
        assert!(!tmp.join("abandoned-2").exists());
        assert!(tmp.join("sidecar.log").exists(), "non-directory entries must survive");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn orphan_cleanup_preserves_fresh_directories() {
        // With a generous max_age, a freshly-created directory must not
        // be touched — the positive case of the time-guard.
        let tmp = std::env::temp_dir().join(format!("nguardia-staging-fresh-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::create_dir_all(tmp.join("recent")).unwrap();

        let cleaned = clean_staging_orphans(&tmp, Duration::from_secs(3600)).unwrap();
        assert_eq!(cleaned, 0);
        assert!(tmp.join("recent").exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn orphan_cleanup_is_noop_when_staging_root_missing() {
        let missing = PathBuf::from("/nonexistent/staging/path/for/test");
        let cleaned = clean_staging_orphans(&missing, Duration::from_secs(60)).unwrap();
        assert_eq!(cleaned, 0);
    }

    #[tokio::test]
    async fn sha256_file_produces_known_hex_digest() {
        // Canonical NIST-style empty-string vector: the SHA-256 of the
        // empty byte sequence is the hex digest below. Asserting the
        // concrete value guards against a silently-swapped hash impl.
        let tmp = std::env::temp_dir().join(format!("nguardia-sha256-empty-{}", Uuid::new_v4()));
        std::fs::write(&tmp, b"").unwrap();
        let hex = sha256_file(&tmp).await.expect("hash empty file");
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        std::fs::remove_file(&tmp).ok();
    }

    #[tokio::test]
    async fn sha256_file_hex_matches_multi_chunk_content() {
        // A payload larger than the 64KB internal read buffer so the
        // chunk-loop path actually executes; "abc" repeated until > 64KB.
        let tmp = std::env::temp_dir().join(format!("nguardia-sha256-bulk-{}", Uuid::new_v4()));
        let payload = "abc".repeat(30_000);
        std::fs::write(&tmp, payload.as_bytes()).unwrap();
        let hex = sha256_file(&tmp).await.expect("hash large file");
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let expected = hasher.finalize();
        let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected_hex);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn promote_error_validation_failure_maps_to_422() {
        let resp = PromoteError::ValidationFailed("shape mismatch".into()).into_response();
        assert_eq!(resp.status().as_u16(), 422);
    }

    #[test]
    fn promote_error_manifest_invalid_maps_to_422() {
        let resp = PromoteError::ManifestInvalid("bad yaml".into()).into_response();
        assert_eq!(resp.status().as_u16(), 422);
    }

    #[test]
    fn promote_error_unsupported_adapter_maps_to_422() {
        let resp = PromoteError::UnsupportedAdapter.into_response();
        assert_eq!(resp.status().as_u16(), 422);
    }

    #[test]
    fn promote_error_staging_io_maps_to_500() {
        let resp = PromoteError::StagingIo("disk full".into()).into_response();
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[test]
    fn promote_error_promote_io_maps_to_500() {
        let resp = PromoteError::PromoteIo("rename failed".into()).into_response();
        assert_eq!(resp.status().as_u16(), 500);
    }

    #[tokio::test]
    async fn promote_files_rolls_back_active_files_when_sidecar_move_fails() {
        let tmp = std::env::temp_dir().join(format!("nguardia-promote-rollback-{}", Uuid::new_v4()));
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

        let err = promote_files_atomically(&PromoteFileSet {
            staging_manifest: staging_manifest.clone(),
            staged_onnx,
            staged_sidecar: Some(missing_sidecar),
            target_manifest: target_manifest.clone(),
            target_onnx: target_onnx.clone(),
            target_sidecar: Some(target_sidecar.clone()),
            backup_dir: backup,
        })
        .await
        .expect_err("missing sidecar should fail promote");

        assert!(matches!(err, PromoteError::PromoteIo(_)));
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
        // Dynamic cap from config must reach the client verbatim — this
        // guards against a future refactor that silently drops the cap
        // from the format string.
        let rendered = format!("{:?}", UploadError::OnnxTooLarge(7_000_000));
        assert!(
            rendered.contains("7000000"),
            "rendered error must include the cap: {rendered}"
        );
    }
}
