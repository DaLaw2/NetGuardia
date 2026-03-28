use actix_web::{web, HttpResponse, Scope};
use serde::Deserialize;

use crate::adapter::persistence::Database;
use crate::core::auth::extractor::AuthClaims;

pub fn initialize() -> Scope {
    web::scope("/mcp-keys")
        .route("", web::get().to(list_keys))
        .route("/generate", web::post().to(generate_key))
        .route("/{id}", web::delete().to(delete_key))
}

async fn list_keys(
    _auth: AuthClaims,
    db: web::Data<Database>,
) -> HttpResponse {
    match db.list_mcp_keys() {
        Ok(keys) => {
            let responses: Vec<serde_json::Value> = keys.into_iter().map(|(id, name, level, created, last_used)| {
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "permission_level": level,
                    "created_at": created,
                    "last_used_at": last_used,
                })
            }).collect();
            HttpResponse::Ok().json(responses)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[derive(Deserialize)]
struct GenerateKeyRequest {
    name: String,
    level: Option<String>,
}

async fn generate_key(
    _auth: AuthClaims,
    db: web::Data<Database>,
    body: web::Json<GenerateKeyRequest>,
) -> HttpResponse {
    use rand::Rng;
    use rand::distr::Alphanumeric;

    let raw_key: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    use sha2::{Sha256, Digest};
    let key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(raw_key.as_bytes());
        format!("{:x}", hasher.finalize())
    };

    let level = body.level.as_deref().unwrap_or("read_only");

    match db.insert_mcp_key(&key_hash, &body.name, level) {
        Ok(id) => {
            HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "key": raw_key,
                "name": body.name,
                "permission_level": level,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_key(
    _auth: AuthClaims,
    db: web::Data<Database>,
    path: web::Path<i64>,
) -> HttpResponse {
    let id = path.into_inner();
    match db.delete_mcp_key(id) {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Key not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
