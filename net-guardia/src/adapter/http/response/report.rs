use actix_web::{HttpResponse, Scope, web};
use tokio_util::io::ReaderStream;

use crate::adapter::http::helpers::{internal_error, ok_json_or_error};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::reporting::report_delivery::ReportDeliveryService;
use crate::core::reporting::report_generation::ReportGenerationService;
use crate::domain::report::error::ReportError;

pub fn initialize() -> Scope {
    web::scope("/report")
        .route("/generate", web::post().to(generate_report))
        .route("/data", web::get().to(report_data))
        .route("/send", web::post().to(send_report))
}

async fn generate_report(_auth: AuthClaims, reports: web::Data<ReportGenerationService>) -> HttpResponse {
    match reports.generate_html_report().await {
        Ok(path) => match tokio::fs::File::open(&path).await {
            Ok(file) => {
                let filename = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "report.html".into());
                let stream = ReaderStream::new(file);
                HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .insert_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                    .streaming(stream)
            }
            Err(_) => HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "path": path.to_string_lossy(),
                "message": "HTML report generated."
            })),
        },
        Err(e) => internal_error(e),
    }
}

async fn report_data(_auth: AuthClaims, reports: web::Data<ReportGenerationService>) -> HttpResponse {
    ok_json_or_error(reports.report_data().await)
}

async fn send_report(_auth: AuthClaims, delivery: web::Data<ReportDeliveryService>) -> HttpResponse {
    match delivery.send_weekly_report_now().await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Report sent successfully."
        })),
        Err(ReportError::SmtpNotConfigured) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "SMTP not configured. Ensure smtp_host, smtp_port, smtp_username, smtp_password are set, and that the sender address (smtp_sender or smtp_username) contains '@'."
        })),
        Err(ReportError::RecipientMissing) => HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "No smtp_recipient configured."
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}
