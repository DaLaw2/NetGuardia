use actix_web::{web, HttpResponse, Scope};

use crate::adapter::persistence::Database;
use crate::core::auth::extractor::AuthClaims;
use crate::core::report::engine;
use crate::interface::port::repository::RepositoryPort;

pub fn initialize() -> Scope {
    web::scope("/report")
        .route("/generate", web::post().to(generate_report))
        .route("/data", web::get().to(report_data))
}

async fn generate_report(
    _auth: AuthClaims,
    db: web::Data<Database>,
) -> HttpResponse {
    let db_ref = db.get_ref();
    match engine::generate_html_report(db_ref as &dyn RepositoryPort, "/tmp/netguardia-reports") {
        Ok(path) => {
            match std::fs::read(&path) {
                Ok(content) => {
                    HttpResponse::Ok()
                        .content_type("text/html; charset=utf-8")
                        .insert_header(("Content-Disposition", format!(
                            "attachment; filename=\"{}\"",
                            path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "report.html".into())
                        )))
                        .body(content)
                }
                Err(_) => {
                    HttpResponse::Ok().json(serde_json::json!({
                        "success": true,
                        "path": path.to_string_lossy(),
                        "message": "HTML report generated."
                    }))
                }
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn report_data(
    _auth: AuthClaims,
    db: web::Data<Database>,
) -> HttpResponse {
    let db_ref = db.get_ref();
    match engine::generate_report_json(db_ref as &dyn RepositoryPort) {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
