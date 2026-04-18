//! Multipart upload surface for BYO model files. Accepts a `manifest`
//! YAML field plus an `onnx` binary field, streams each to
//! `models/.staging/<uuid>/` with enforced size caps, and leaves atomic
//! promotion to `models/` for the model-watcher hot-reload flow to
//! handle after I-6 wires validation + rename.
//!
//! Scope here: body-size caps, streaming-to-disk (never buffering the
//! full `.onnx` in RAM), filename-collision safety via UUID subdir, and
//! cheap up-front sanity on the ONNX header. Structural schema
//! validation against `MLInferenceConfig` is the next milestone's job.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{HttpResponse, Responder, Scope, web};
use futures_util::TryStreamExt;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::infrastructure::app_config::AppConfig;
use crate::model::config::constants::{MODELS_DIR, STAGING_SUBDIR};

/// Hard ceiling on the `.onnx` stream. Anything larger is either a
/// mistake or an attempt to DoS the disk.
pub const MAX_ONNX_BYTES: usize = 100 * 1024 * 1024;

/// Hard ceiling on the `manifest` YAML stream. Real manifests are a few
/// kilobytes at most; this leaves headroom without allowing blob
/// smuggling through the field.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// Multipart field names the client must use. Stable wire contract —
/// the frontend form generator depends on these exact strings.
const FIELD_MANIFEST: &str = "manifest";
const FIELD_ONNX: &str = "onnx";

/// Number of bytes of the ONNX body we inspect up-front for an obvious
/// non-Protobuf header. A fuller structural check (shape vs manifest
/// declared `features`) runs during `build_adapter` in the promote path.
const ONNX_SNIFF_BYTES: usize = 16;

pub fn initialize() -> Scope {
    web::scope("/models").route("/upload", web::post().to(upload))
}

/// `POST /api/ml/models/upload` — multipart with `manifest` (YAML text)
/// and `onnx` (binary) fields. Writes both to a fresh
/// `models/.staging/<uuid>/` and returns the staging id + byte counts.
async fn upload(app_config: web::Data<Arc<AppConfig>>, payload: Multipart) -> impl Responder {
    let _ = app_config; // kept for future per-tenant staging roots

    let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
    let staging_id = Uuid::new_v4().to_string();
    let staging_dir = staging_root.join(&staging_id);

    match ingest_multipart(payload, &staging_dir).await {
        Ok(summary) => HttpResponse::Ok().json(serde_json::json!({
            "staging_id": staging_id,
            "manifest_bytes": summary.manifest_bytes,
            "onnx_bytes": summary.onnx_bytes,
            "onnx_filename": summary.onnx_filename,
        })),
        Err(kind) => {
            // Best-effort teardown so orphan staging dirs don't
            // accumulate from failed uploads.
            let _ = fs::remove_dir_all(&staging_dir).await;
            kind.into_response()
        }
    }
}

/// Successful-path metadata the handler surfaces to the client.
#[derive(Debug)]
struct UploadSummary {
    manifest_bytes: usize,
    onnx_bytes: usize,
    onnx_filename: String,
}

/// Errors that can surface a specific HTTP response. Kept in-module
/// because none of these have callers outside this handler.
#[derive(Debug)]
enum UploadError {
    MissingField(&'static str),
    DuplicateField(&'static str),
    UnknownField(String),
    ManifestTooLarge,
    OnnxTooLarge,
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
            Self::ManifestTooLarge => (413, format!("manifest exceeds {MAX_MANIFEST_BYTES} bytes")),
            Self::OnnxTooLarge => (413, format!("onnx exceeds {MAX_ONNX_BYTES} bytes")),
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

async fn ingest_multipart(mut payload: Multipart, staging_dir: &Path) -> Result<UploadSummary, UploadError> {
    fs::create_dir_all(staging_dir)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;

    let mut manifest_written: Option<usize> = None;
    let mut onnx_summary: Option<(String, usize)> = None;

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
                let dest = staging_dir.join("manifest.yaml");
                let written = stream_field_to_file(&mut field, &dest, MAX_MANIFEST_BYTES, false).await?;
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
                let written = stream_field_to_file(&mut field, &dest, MAX_ONNX_BYTES, true).await?;
                onnx_summary = Some((onnx_filename, written));
            }
            other => {
                return Err(UploadError::UnknownField(other.to_string()));
            }
        }
    }

    let manifest_bytes = manifest_written.ok_or(UploadError::MissingField(FIELD_MANIFEST))?;
    let (onnx_filename, onnx_bytes) = onnx_summary.ok_or(UploadError::MissingField(FIELD_ONNX))?;

    Ok(UploadSummary {
        manifest_bytes,
        onnx_bytes,
        onnx_filename,
    })
}

/// Stream a multipart field directly to disk. Aborts (and leaves the
/// caller to clean up) when the declared byte cap is exceeded or when
/// the binary sniff rejects the first chunk.
async fn stream_field_to_file(
    field: &mut actix_multipart::Field,
    dest: &Path,
    max_bytes: usize,
    sniff_onnx: bool,
) -> Result<usize, UploadError> {
    let mut file = fs::File::create(dest)
        .await
        .map_err(|e| UploadError::StagingSetupFailure(e.to_string()))?;
    let mut total = 0usize;
    let mut sniffed = !sniff_onnx;

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
            return Err(if sniff_onnx {
                UploadError::OnnxTooLarge
            } else {
                UploadError::ManifestTooLarge
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

/// Remove staging subdirectories older than `max_age`. Runs on startup
/// and on a periodic timer so failed uploads don't accumulate.
pub fn clean_staging_orphans(staging_root: &Path, max_age: std::time::Duration) -> std::io::Result<usize> {
    if !staging_root.exists() {
        return Ok(0);
    }
    let now = std::time::SystemTime::now();
    let mut cleaned = 0usize;
    for entry in std::fs::read_dir(staging_root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let metadata = entry.metadata()?;
        let mtime = metadata.modified()?;
        let age = now.duration_since(mtime).unwrap_or_default();
        if age >= max_age {
            std::fs::remove_dir_all(&path)?;
            cleaned += 1;
        }
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

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
}
