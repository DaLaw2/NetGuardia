use actix_web::{HttpResponse, Scope, web};

use crate::adapter::persistence::Database;
use crate::core::auth::extractor::AuthClaims;
use crate::core::email::scheduler::SmtpClient;
use crate::core::report::engine;
use crate::infrastructure::secret_store::SecretStore;
use crate::interface::port::repository::RepositoryPort;
use crate::interface::port::secret_store::SecretStorePort;
pub fn initialize() -> Scope {
    web::scope("/report")
        .route("/generate", web::post().to(generate_report))
        .route("/data", web::get().to(report_data))
        .route("/send", web::post().to(send_report))
}

async fn generate_report(_auth: AuthClaims, db: web::Data<Database>) -> HttpResponse {
    let report_dir = db
        .get_setting("report_dir")
        .ok()
        .flatten()
        .unwrap_or_else(|| "/var/lib/netguardia/reports".to_string());
    if let Err(e) = std::fs::create_dir_all(&report_dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create report directory: {}", e)
        }));
    }
    let db_ref = db.get_ref();
    match engine::generate_html_report(db_ref as &dyn RepositoryPort, &report_dir) {
        Ok(path) => match std::fs::read(&path) {
            Ok(content) => HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .insert_header((
                    "Content-Disposition",
                    format!(
                        "attachment; filename=\"{}\"",
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "report.html".into())
                    ),
                ))
                .body(content),
            Err(_) => HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "path": path.to_string_lossy(),
                "message": "HTML report generated."
            })),
        },
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn report_data(_auth: AuthClaims, db: web::Data<Database>) -> HttpResponse {
    let db_ref = db.get_ref();
    match engine::generate_report_json(db_ref as &dyn RepositoryPort) {
        Ok(data) => HttpResponse::Ok().json(data),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// Manually trigger: generate the weekly report and send it via SMTP now.
async fn send_report(_auth: AuthClaims, db: web::Data<Database>, secrets: web::Data<SecretStore>) -> HttpResponse {
    let db_ref = db.get_ref() as &dyn RepositoryPort;
    let secrets_ref = secrets.get_ref() as &dyn SecretStorePort;

    let smtp = match SmtpClient::from_database(db_ref, Some(secrets_ref)) {
        Ok(Some(client)) => client,
        Ok(None) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "SMTP not configured. Ensure smtp_host, smtp_port, smtp_username, smtp_password are set, and that the sender address (smtp_sender or smtp_username) contains '@'."
            }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to read SMTP settings: {e}")
            }));
        }
    };

    let recipient = match db_ref.get_setting("smtp_recipient") {
        Ok(Some(r)) if !r.is_empty() => r,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "error": "No smtp_recipient configured."
            }));
        }
    };

    let html = match crate::core::email::report::generate_weekly_report(db_ref) {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to generate report: {e}")
            }));
        }
    };

    let subject = format!("NetGuardia Weekly Report — {}", chrono::Local::now().format("%Y-%m-%d"));

    let send_result = tokio::task::spawn_blocking(move || smtp.send(&recipient, &subject, &html)).await;

    match send_result {
        Ok(Ok(())) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Report sent successfully."
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to send report: {e}")
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Send task panicked: {e}")
        })),
    }
}
