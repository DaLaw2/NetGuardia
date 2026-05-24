use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use actix_files::NamedFile;
use actix_web::{HttpRequest, HttpResponse, Responder, Scope, web};

use crate::adapter::flow_trace_store::FsFlowTraceStore;
use crate::adapter::http::helpers::{bad_request, forbidden, internal_error, not_found};
use crate::core::inference::engine::Engine;
use crate::interface::detection::flow_trace_store::{FLOW_TRACE_FILE_EXT, FLOW_TRACE_FILE_MARKER, FlowTraceStore};

pub fn initialize() -> Scope {
    web::scope("/flow-trace")
        .route("/files", web::get().to(list_files))
        .route("/download/{name}", web::get().to(download))
}

async fn list_files(engine: web::Data<Engine>) -> impl Responder {
    let Some(directory) = flow_trace_directory(&engine) else {
        return HttpResponse::Ok().json(serde_json::json!({ "files": [], "enabled": false }));
    };

    let store = FsFlowTraceStore;
    match store.list_files(&directory) {
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
        Err(e) => internal_error(format!("failed to list flow-trace directory: {e}")),
    }
}

async fn download(
    req: HttpRequest,
    path: web::Path<String>,
    engine: web::Data<Engine>,
) -> actix_web::Result<HttpResponse> {
    let name = path.into_inner();
    if !is_safe_flow_trace_name(&name) {
        return Ok(bad_request("invalid flow-trace filename"));
    }

    let Some(directory) = flow_trace_directory(&engine) else {
        return Ok(not_found("Flow Trace recording is not enabled"));
    };

    let file_path = directory.join(&name);
    match is_regular_flow_trace_file(&file_path) {
        Ok(true) => {}
        Ok(false) => return Ok(forbidden("flow-trace file must be a regular file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(not_found("flow-trace file not found")),
        Err(e) => return Ok(internal_error(format!("failed to inspect flow-trace file: {e}"))),
    }

    let named = NamedFile::open_async(&file_path).await?;
    Ok(named.into_response(&req))
}

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

fn flow_trace_directory(engine: &web::Data<Engine>) -> Option<PathBuf> {
    engine.traffic_logger_directory().map(Path::to_path_buf)
}

fn is_regular_flow_trace_file(path: &Path) -> io::Result<bool> {
    let meta = fs::symlink_metadata(path)?;
    Ok(meta.file_type().is_file())
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

    #[cfg(unix)]
    #[test]
    fn regular_file_check_rejects_symlink() {
        let dir = std::env::temp_dir().join(format!("netguardia-flow-trace-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("temp dir");
        let target = dir.join("outside.txt");
        let link = dir.join("flow-trace-00000000000000000001.csv");
        fs::write(&target, b"secret").expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let result = is_regular_flow_trace_file(&link).expect("metadata");

        fs::remove_dir_all(&dir).expect("cleanup");
        assert!(!result);
    }
}
