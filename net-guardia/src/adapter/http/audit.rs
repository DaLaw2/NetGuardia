use actix_web::{HttpResponse, Scope, web};

use crate::adapter::persistence::Database;
use crate::core::auth::extractor::AuthClaims;
use crate::interface::port::audit::AuditRepo;
use crate::model::error::Error;
use crate::model::error::database::DatabaseError;

pub fn initialize() -> Scope {
    web::scope("/audit")
        .route("", web::get().to(list_audit_logs))
        .route("/verify", web::get().to(verify_chain))
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

/// `GET /api/audit/verify` — walk the WORM hash chain and report whether
/// every row_hash still matches `H(ts || actor || action || detail ||
/// prev_hash)`. Surfaces over HTTP the same verification the CLI's
/// `--verify-audit-log` flag performs, so auditors can check chain
/// integrity without shell access. Any mismatch returns the offending
/// row id inside `error` so the dashboard can link straight to it.
async fn verify_chain(_auth: AuthClaims, audit: web::Data<dyn AuditRepo>) -> HttpResponse {
    match audit.verify_audit_log_chain() {
        Ok(count) => HttpResponse::Ok().json(serde_json::json!({
            "chain_intact": true,
            "verified": count,
        })),
        Err(e) => {
            // Tamper detection is a successful verify outcome, not a server
            // failure — return 200 with `chain_intact: false` so frontend
            // retry/error handling treats real chain corruption as a
            // distinct condition from transient DB connectivity issues.
            // Reserve 500 for actual DB/IO failures.
            let prev_mismatch = matches!(&e, Error::Database(DatabaseError::AuditPrevHashMismatch { .. }));
            let row_mismatch = matches!(&e, Error::Database(DatabaseError::AuditRowHashMismatch { .. }));
            if prev_mismatch || row_mismatch {
                let kind = if prev_mismatch {
                    "prev_hash_mismatch"
                } else {
                    "row_hash_mismatch"
                };
                HttpResponse::Ok().json(serde_json::json!({
                    "chain_intact": false,
                    "verified": 0,
                    "kind": kind,
                    "detail": e.to_string(),
                }))
            } else {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "chain_intact": null,
                    "verified": 0,
                    "error": e.to_string(),
                }))
            }
        }
    }
}
