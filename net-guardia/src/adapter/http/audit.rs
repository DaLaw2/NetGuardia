use actix_web::{HttpResponse, Scope, web};

use crate::adapter::persistence::Database;
use crate::core::auth::extractor::AuthClaims;

pub fn initialize() -> Scope {
    web::scope("/audit").route("", web::get().to(list_audit_logs))
}

async fn list_audit_logs(_auth: AuthClaims, db: web::Data<Database>) -> HttpResponse {
    match db.list_audit_logs() {
        Ok(entries) => {
            let json: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "actor": e.actor,
                        "action": e.action,
                        "detail": e.detail,
                        "created_at": e.created_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(json)
        }
        Err(_) => HttpResponse::Ok().json(serde_json::json!([])),
    }
}
