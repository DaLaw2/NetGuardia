use actix_web::{HttpResponse, Scope, web};

use crate::adapter::http::helpers::internal_error;
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::common::error::Error;
use crate::common::error::database::DatabaseError;
use crate::interface::system::audit::AuditRepo;

pub fn initialize() -> Scope {
    web::scope("/audit")
        .route("", web::get().to(list_audit_logs))
        .route("/verify", web::get().to(verify_chain))
}

async fn list_audit_logs(_auth: AuthClaims, audit: web::Data<dyn AuditRepo>) -> HttpResponse {
    match audit.list_audit_logs().await {
        Ok(entries) => HttpResponse::Ok().json(entries),
        Err(e) => internal_error(e),
    }
}

async fn verify_chain(_auth: AuthClaims, audit: web::Data<dyn AuditRepo>) -> HttpResponse {
    match audit.verify_audit_log_chain(0).await {
        Ok((count, _last_id)) => HttpResponse::Ok().json(serde_json::json!({
            "chain_intact": true,
            "verified": count,
        })),
        Err(e) => {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::http::StatusCode;
    use async_trait::async_trait;

    use super::*;
    use crate::domain::common::audit::AuditLogEntry;
    use crate::domain::identity::auth::Claims;

    struct FailingAuditRepo;

    fn test_error() -> Error {
        DatabaseError::PersistedValueInvalid("audit_log", "detail", "bad").into()
    }

    #[async_trait]
    impl AuditRepo for FailingAuditRepo {
        async fn insert_audit_log(&self, _actor: &str, _action: &str, _detail: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn list_audit_logs(&self) -> Result<Vec<AuditLogEntry>, Error> {
            Err(test_error())
        }

        async fn list_audit_logs_by_src_ip(&self, _src_ip: &str, _limit: i64) -> Result<Vec<AuditLogEntry>, Error> {
            Ok(Vec::new())
        }

        async fn verify_audit_log_chain(&self, _after_id: i64) -> Result<(usize, i64), Error> {
            Ok((0, 0))
        }
    }

    fn claims() -> AuthClaims {
        AuthClaims(Claims {
            sub: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            permissions: Vec::new(),
        })
    }

    #[tokio::test]
    async fn list_audit_logs_returns_500_on_repo_error() {
        let repo = web::Data::from(Arc::new(FailingAuditRepo) as Arc<dyn AuditRepo>);

        let response = list_audit_logs(claims(), repo).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
