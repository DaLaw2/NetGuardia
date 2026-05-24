use actix_web::{HttpResponse, Scope, web};
use rand::RngExt;
use rand::distr::Alphanumeric;
use serde::Deserialize;

use crate::adapter::http::helpers::{bad_request, internal_error, not_found};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::domain::identity::auth::PermissionLevel;
use crate::domain::identity::validation::validate_api_key_name;
use crate::interface::identity::api_key::ApiKeyRepo;
use crate::interface::identity::api_key_hasher::ApiKeyHasher;

pub fn initialize() -> Scope {
    web::scope("/api-keys")
        .route("", web::get().to(list_keys))
        .route("/generate", web::post().to(generate_key))
        .route("/{id}", web::delete().to(delete_key))
}

async fn list_keys(_auth: AuthClaims, db: web::Data<dyn ApiKeyRepo>) -> HttpResponse {
    match db.list_api_keys().await {
        Ok(keys) => {
            let responses: Vec<serde_json::Value> = keys
                .into_iter()
                .map(|k| {
                    serde_json::json!({
                        "id": k.id,
                        "name": k.name,
                        "permission_level": k.permission_level,
                        "created_at": k.created_at,
                        "last_used_at": k.last_used_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => internal_error(e),
    }
}

#[derive(Deserialize)]
struct GenerateKeyRequest {
    name: String,
    level: Option<String>,
}

async fn generate_key(
    _auth: AuthClaims,
    db: web::Data<dyn ApiKeyRepo>,
    hasher: web::Data<dyn ApiKeyHasher>,
    body: web::Json<GenerateKeyRequest>,
) -> HttpResponse {
    let raw_key: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let key_hash = hasher.hash_api_key(&raw_key);

    let raw_level = body.level.as_deref().unwrap_or("read_only");
    let Some(level) = PermissionLevel::from_str(raw_level) else {
        return bad_request("Invalid permission level. Must be: read_only, read_write, or full_access");
    };

    let name = body.name.trim();
    if let Err(message) = validate_api_key_name(name) {
        return bad_request(message);
    }

    match db.insert_api_key(&key_hash, name, level.as_str()).await {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "key": raw_key,
            "name": name,
            "permission_level": level.as_str(),
        })),
        Err(e) => internal_error(e),
    }
}

async fn delete_key(_auth: AuthClaims, db: web::Data<dyn ApiKeyRepo>, path: web::Path<i64>) -> HttpResponse {
    let id = path.into_inner();
    match db.delete_api_key(id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => not_found("Key not found"),
        Err(e) => internal_error(e),
    }
}
