use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::UNIX_EPOCH;

use actix_web::{HttpResponse, Scope, web};
use serde::{Deserialize, Serialize};

use crate::core::observability::log_buffer::{self, LogEntry};

/// Hardcoded log directory — not configurable via API to prevent directory traversal.
const LOG_DIR: &str = "logs";

/// Maximum downloadable log file size (50 MB). Prevents OOM from reading huge files.
const MAX_DOWNLOAD_SIZE: u64 = 50 * 1024 * 1024;

/// Default page size for `/live` when the client does not specify `limit`.
/// Chosen so a 2 s poll against a DEBUG-chatty deployment catches up in
/// one round-trip without being absurd payload-wise.
const LIVE_DEFAULT_LIMIT: usize = 500;

/// Hard cap on `/live?limit=` — prevents pathological clients from asking
/// for the entire buffer at once.
const LIVE_MAX_LIMIT: usize = 2_000;

/// Validate log filename: only alphanumeric, dots, underscores, hyphens.
/// Prevents path traversal.
fn is_valid_log_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

pub fn initialize() -> Scope {
    web::scope("/logs")
        .route("", web::get().to(list_logs))
        .route("/live", web::get().to(live_logs))
        .route("/{filename}", web::get().to(download_log))
}

#[derive(Deserialize)]
struct LiveQuery {
    #[serde(default)]
    since_id: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    min_level: Option<String>,
}

#[derive(Serialize)]
struct LiveResponse {
    entries: Vec<LogEntry>,
    next_id: u64,
    total_buffered: usize,
    dropped_oldest: bool,
}

async fn live_logs(query: web::Query<LiveQuery>) -> HttpResponse {
    let since_id = query.since_id.unwrap_or(0);
    let limit = query.limit.unwrap_or(LIVE_DEFAULT_LIMIT).clamp(1, LIVE_MAX_LIMIT);
    let min_severity = query
        .min_level
        .as_deref()
        .map(|s| log_buffer::level_severity(&s.to_ascii_uppercase()))
        .unwrap_or(log_buffer::level_severity("TRACE"));

    let snap = log_buffer::snapshot(since_id, min_severity, limit);
    // Signal to the UI that it lagged enough for the ring to evict rows
    // between polls. Frontend can warn "older entries dropped" without
    // silently skipping a gap.
    let dropped_oldest = since_id > 0 && snap.entries.first().is_some_and(|e| e.id > since_id + 1);
    let next_id = snap.entries.last().map(|e| e.id).unwrap_or(snap.latest_id);

    HttpResponse::Ok().json(LiveResponse {
        entries: snap.entries,
        next_id,
        total_buffered: snap.total,
        dropped_oldest,
    })
}

#[derive(Serialize)]
struct LogFileEntry {
    name: String,
    size: u64,
    modified: Option<u64>,
}

async fn list_logs() -> HttpResponse {
    let log_dir = LOG_DIR;
    let entries = match fs::read_dir(log_dir) {
        Ok(dir) => dir
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let meta = e.metadata().ok()?;
                if !meta.is_file() {
                    return None;
                }
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                Some(LogFileEntry {
                    name,
                    size: meta.len(),
                    modified,
                })
            })
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };

    HttpResponse::Ok().json(serde_json::json!({ "files": entries }))
}

async fn download_log(path: web::Path<String>) -> HttpResponse {
    let filename = path.into_inner();

    if !is_valid_log_filename(&filename) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid filename: only alphanumeric, dots, underscores, hyphens allowed"
        }));
    }

    let file_path = Path::new(LOG_DIR).join(&filename);

    // Canonicalize to prevent symlink traversal
    let canonical = match fs::canonicalize(&file_path) {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Log file '{}' not found", filename)
            }));
        }
    };
    if let Ok(log_dir_canonical) = fs::canonicalize(LOG_DIR)
        && !canonical.starts_with(&log_dir_canonical)
    {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied: file is outside the log directory"
        }));
    }

    // Check file size before reading to prevent OOM on large logs
    match fs::metadata(&canonical) {
        Ok(meta) if meta.len() > MAX_DOWNLOAD_SIZE => {
            return HttpResponse::PayloadTooLarge().json(serde_json::json!({
                "error": format!("Log file exceeds maximum download size ({}MB)", MAX_DOWNLOAD_SIZE / 1024 / 1024)
            }));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Log file '{}' not found", filename)
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read log file: {}", e)
            }));
        }
        Ok(_) => {}
    }

    let content = match fs::read(&canonical) {
        Ok(bytes) => bytes,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read log file: {}", e)
            }));
        }
    };

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .body(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_filenames() {
        assert!(is_valid_log_filename("NetGuardia.2026-03-30"));
        assert!(is_valid_log_filename("app.log"));
        assert!(is_valid_log_filename("debug_2026-03-30.log"));
    }

    #[test]
    fn path_traversal_blocked() {
        assert!(!is_valid_log_filename("../../etc/passwd"));
        assert!(!is_valid_log_filename("../secret"));
        assert!(!is_valid_log_filename("/etc/shadow"));
    }

    #[test]
    fn special_chars_blocked() {
        assert!(!is_valid_log_filename("file;rm -rf"));
        assert!(!is_valid_log_filename("log file.txt"));
        assert!(!is_valid_log_filename(""));
    }

    #[test]
    fn too_long_blocked() {
        let long = "a".repeat(129);
        assert!(!is_valid_log_filename(&long));
        let exact = "a".repeat(128);
        assert!(is_valid_log_filename(&exact));
    }
}
