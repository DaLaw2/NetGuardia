use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Scope, web};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;

use crate::adapter::http::helpers::{bad_request, forbidden, internal_error, json_error, not_found};
use crate::common::utils::log_level::level_severity;
use crate::domain::common::config::AppConfig;
use crate::interface::system::live_logs::{LiveLogQuery, LogEntry};

fn is_valid_log_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
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

async fn live_logs(
    query: web::Query<LiveQuery>,
    app_config: web::Data<ArcSwap<AppConfig>>,
    buf: web::Data<dyn LiveLogQuery>,
) -> HttpResponse {
    let since_id = query.since_id.unwrap_or(0);
    let obs = app_config.load().observability.clone();
    let limit = query
        .limit
        .unwrap_or(obs.log_live_default_limit)
        .clamp(1, obs.log_live_max_limit.max(1));
    let min_severity = query
        .min_level
        .as_deref()
        .map(|s| level_severity(&s.to_ascii_uppercase()))
        .unwrap_or(level_severity("TRACE"));

    let snap = buf.snapshot(since_id, min_severity, limit);
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

async fn list_logs(app_config: web::Data<ArcSwap<AppConfig>>) -> HttpResponse {
    let log_dir = app_config.load().system.log_dir.clone();
    let entries = match list_log_files(Path::new(&log_dir)) {
        Ok(entries) => entries,
        Err(e) => return internal_error(format!("Failed to list log files: {}", e)),
    };

    HttpResponse::Ok().json(serde_json::json!({ "files": entries }))
}

fn list_log_files(log_dir: &Path) -> io::Result<Vec<LogFileEntry>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata()?;
        if !meta.is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        files.push(LogFileEntry {
            name,
            size: meta.len(),
            modified,
        });
    }
    Ok(files)
}

async fn download_log(path: web::Path<String>, app_config: web::Data<ArcSwap<AppConfig>>) -> HttpResponse {
    let config = app_config.load();
    let max_download_size = config.observability.log_max_download_size;
    let log_dir = PathBuf::from(&config.system.log_dir);
    let filename = path.into_inner();

    if !is_valid_log_filename(&filename) {
        return bad_request("Invalid filename: only alphanumeric, dots, underscores, hyphens allowed");
    }

    let file_path = log_dir.join(&filename);
    let canonical = match fs::canonicalize(&file_path) {
        Ok(p) => p,
        Err(_) => return not_found(format!("Log file '{}' not found", filename)),
    };
    if let Ok(log_dir_canonical) = fs::canonicalize(&log_dir)
        && !canonical.starts_with(&log_dir_canonical)
    {
        return forbidden("Access denied: file is outside the log directory");
    }
    match fs::metadata(&canonical) {
        Ok(meta) if meta.len() > max_download_size => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "Log file exceeds maximum download size ({}MB)",
                    max_download_size / 1024 / 1024
                ),
            );
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return not_found(format!("Log file '{}' not found", filename)),
        Err(e) => return internal_error(format!("Failed to read log file: {}", e)),
        Ok(_) => {}
    }

    let file = match tokio::fs::File::open(&canonical).await {
        Ok(f) => f,
        Err(e) => return internal_error(format!("Failed to open log file: {}", e)),
    };
    let stream = ReaderStream::new(file);

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/octet-stream"))
        .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
        .streaming(stream)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        assert!(!is_valid_log_filename("."));
        assert!(!is_valid_log_filename(".."));
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

    #[test]
    fn missing_log_dir_is_reported() {
        let path = temp_path("net-guardia-missing");

        assert!(list_log_files(&path).is_err());
    }

    #[test]
    fn list_log_files_ignores_directories() {
        let dir = temp_path("net-guardia-logs");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("app.log"), b"hello").unwrap();
        fs::create_dir(dir.join("nested")).unwrap();

        let files = list_log_files(&dir).unwrap();

        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "app.log");
        assert_eq!(files[0].size, 5);
    }

    fn temp_path(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }
}
