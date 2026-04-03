use actix_web::{HttpResponse, Scope, web};
use serde::Serialize;

/// Hardcoded log directory — not configurable via API to prevent directory traversal.
const LOG_DIR: &str = "logs";

/// Maximum downloadable log file size (50 MB). Prevents OOM from reading huge files.
const MAX_DOWNLOAD_SIZE: u64 = 50 * 1024 * 1024;

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
        .route("/{filename}", web::get().to(download_log))
}

#[derive(Serialize)]
struct LogFileEntry {
    name: String,
    size: u64,
    modified: Option<u64>,
}

async fn list_logs() -> HttpResponse {
    let log_dir = LOG_DIR;
    let entries = match std::fs::read_dir(log_dir) {
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
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
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

    let file_path = std::path::Path::new(LOG_DIR).join(&filename);

    // Canonicalize to prevent symlink traversal
    let canonical = match std::fs::canonicalize(&file_path) {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Log file '{}' not found", filename)
            }));
        }
    };
    if let Ok(log_dir_canonical) = std::fs::canonicalize(LOG_DIR)
        && !canonical.starts_with(&log_dir_canonical)
    {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Access denied: file is outside the log directory"
        }));
    }

    // Check file size before reading to prevent OOM on large logs
    match std::fs::metadata(&canonical) {
        Ok(meta) if meta.len() > MAX_DOWNLOAD_SIZE => {
            return HttpResponse::PayloadTooLarge().json(serde_json::json!({
                "error": format!("Log file exceeds maximum download size ({}MB)", MAX_DOWNLOAD_SIZE / 1024 / 1024)
            }));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
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

    let content = match std::fs::read(&canonical) {
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
