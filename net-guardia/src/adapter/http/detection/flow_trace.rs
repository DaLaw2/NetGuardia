//! HTTP surface for Flow Trace recording. Exposes the rotated CSV
//! shards the writer thread produces so analysts can pull them for
//! offline training / audit.
//!
//! Range support via `actix_files::NamedFile` — the frontend's download
//! progress bar needs `Content-Range` to show % complete on large files.

use std::path::{Path, PathBuf};

use actix_files::NamedFile;
use actix_web::{HttpRequest, HttpResponse, Responder, Scope, web};

use crate::core::inference::engine::Engine;
use crate::core::inference::traffic_logger::list_flow_trace_files;
use crate::domain::common::config::constants::{FLOW_TRACE_FILE_EXT, FLOW_TRACE_FILE_MARKER};

pub fn initialize() -> Scope {
    web::scope("/flow-trace")
        .route("/files", web::get().to(list_files))
        .route("/download/{name}", web::get().to(download))
}

/// `GET /api/flow-trace/files` — JSON summary of every rotated CSV in
/// the recording directory. Sorted oldest-first so clients showing a
/// retention list get a stable order.
async fn list_files(engine: web::Data<Engine>) -> impl Responder {
    let Some(directory) = flow_trace_directory(&engine) else {
        return HttpResponse::Ok().json(serde_json::json!({ "files": [], "enabled": false }));
    };

    match list_flow_trace_files(&directory) {
        Ok(files) => {
            let json_files: Vec<serde_json::Value> = files
                .into_iter()
                .map(|f| {
                    serde_json::json!({
                        "name": f.name,
                        "size_bytes": f.size_bytes,
                        "modified_unix_secs": f.modified_unix_secs,
                    })
                })
                .collect();
            HttpResponse::Ok().json(serde_json::json!({
                "files": json_files,
                "enabled": true,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("failed to list flow-trace directory: {e}"),
        })),
    }
}

/// `GET /api/flow-trace/download/{name}` — streams a single rotated
/// shard with range support.
async fn download(req: HttpRequest, engine: web::Data<Engine>) -> actix_web::Result<HttpResponse> {
    let name = match req.match_info().get("name") {
        Some(n) => n.to_string(),
        None => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "missing filename path segment",
            })));
        }
    };

    if !is_safe_flow_trace_name(&name) {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid flow-trace filename",
        })));
    }

    let Some(directory) = flow_trace_directory(&engine) else {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "Flow Trace recording is not enabled",
        })));
    };

    let file_path = directory.join(&name);
    if !file_path.is_file() {
        return Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "flow-trace file not found",
        })));
    }

    let named = NamedFile::open_async(&file_path).await?;
    Ok(named.into_response(&req))
}

/// Reject anything that isn't a plain `flow-trace-<digits>.csv` entry.
/// Traversal sequences and empty / renamed files get zero chance to
/// escape the recording directory.
pub fn is_safe_flow_trace_name(name: &str) -> bool {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return false;
    }
    let Some(stripped) = name.strip_prefix(FLOW_TRACE_FILE_MARKER) else {
        return false;
    };
    let Some(suffix) = stripped.strip_suffix(FLOW_TRACE_FILE_EXT) else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
}

/// Resolve the Flow Trace recording directory from the shared
/// `Engine` if the logger is active. Returns `None` when Flow Trace
/// isn't enabled (Dormant state).
fn flow_trace_directory(engine: &web::Data<Engine>) -> Option<PathBuf> {
    engine.traffic_logger_directory().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_name_accepts_canonical_flow_trace_file() {
        assert!(is_safe_flow_trace_name("flow-trace-00000000000000000042.csv"));
        assert!(is_safe_flow_trace_name("flow-trace-17150000000000000000.csv"));
    }

    #[test]
    fn safe_name_rejects_traversal_sequences() {
        assert!(!is_safe_flow_trace_name("../etc/passwd"));
        assert!(!is_safe_flow_trace_name("flow-trace-../x.csv"));
        assert!(!is_safe_flow_trace_name("../flow-trace-1.csv"));
        assert!(!is_safe_flow_trace_name("flow-trace-1/.csv"));
        assert!(!is_safe_flow_trace_name("flow-trace-1\\.csv"));
    }

    #[test]
    fn safe_name_rejects_unrelated_prefixes_and_suffixes() {
        assert!(!is_safe_flow_trace_name("config.csv"));
        assert!(!is_safe_flow_trace_name("flow-trace-42.txt"));
        assert!(!is_safe_flow_trace_name(""));
    }

    #[test]
    fn safe_name_rejects_non_numeric_suffix() {
        assert!(!is_safe_flow_trace_name("flow-trace-.csv"));
        assert!(!is_safe_flow_trace_name("flow-trace-abc.csv"));
        assert!(!is_safe_flow_trace_name("flow-trace-12abc.csv"));
    }
}
