use std::fs;

use actix_web::{HttpResponse, Scope, web};
use arc_swap::ArcSwap;
use chrono::Local;
use tokio::task::spawn_blocking;

use crate::adapter::http::helpers::ok_json_or_error;
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::adapter::notification::smtp::SmtpClient;
use crate::adapter::persistence::Database;
use crate::core::reporting::email_report::generate_weekly_report;
use crate::core::reporting::report_engine;
use crate::domain::common::config::AppConfig;
use crate::domain::common::error::misc::MiscError;
use crate::infrastructure::secret_store::SecretStore;
use crate::interface::report_snapshot::ReportSnapshotRepo;
use crate::interface::secret_store::SecretStorePort;

pub fn initialize() -> Scope {
    web::scope("/report")
        .route("/generate", web::post().to(generate_report))
        .route("/data", web::get().to(report_data))
        .route("/send", web::post().to(send_report))
}

async fn generate_report(
    _auth: AuthClaims,
    db: web::Data<Database>,
    config: web::Data<ArcSwap<AppConfig>>,
) -> HttpResponse {
    let report_dir = config.load().system.report_dir.clone();
    if let Err(e) = fs::create_dir_all(&report_dir) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create report directory: {}", e)
        }));
    }
    let db_ref = db.get_ref();
    match report_engine::generate_html_report(db_ref as &dyn ReportSnapshotRepo, &report_dir).await {
        Ok(path) => match fs::read(&path) {
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
    ok_json_or_error(report_engine::generate_report_json(db_ref as &dyn ReportSnapshotRepo).await)
}

/// Manually trigger: generate the weekly report and send it via SMTP now.
async fn send_report(
    _auth: AuthClaims,
    db: web::Data<Database>,
    config: web::Data<ArcSwap<AppConfig>>,
    secrets: web::Data<SecretStore>,
) -> HttpResponse {
    let db_ref = db.get_ref() as &dyn ReportSnapshotRepo;
    let secrets_ref = secrets.get_ref() as &dyn SecretStorePort;
    let smtp_cfg = config.load().notification.smtp.clone();

    let smtp = match SmtpClient::from_config(&smtp_cfg, Some(secrets_ref)).await {
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

    let recipient = smtp_cfg.recipient;
    if recipient.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": MiscError::ValidationError("No smtp_recipient configured.").to_string()
        }));
    }

    let html = match generate_weekly_report(db_ref).await {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to generate report: {e}")
            }));
        }
    };

    let subject = format!("NetGuardia Weekly Report — {}", Local::now().format("%Y-%m-%d"));

    let send_result = spawn_blocking(move || smtp.send(&recipient, &subject, &html)).await;

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
