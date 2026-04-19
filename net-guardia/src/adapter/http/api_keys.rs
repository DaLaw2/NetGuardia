use actix_web::{HttpResponse, Scope, web};
use serde::Deserialize;

use crate::core::auth::extractor::AuthClaims;
use crate::interface::port::api_key::ApiKeyRepo;

pub fn initialize() -> Scope {
    web::scope("/api-keys")
        .route("", web::get().to(list_keys))
        .route("/generate", web::post().to(generate_key))
        .route("/{id}", web::delete().to(delete_key))
}

async fn list_keys(_auth: AuthClaims, db: web::Data<dyn ApiKeyRepo>) -> HttpResponse {
    match db.list_api_keys() {
        Ok(keys) => {
            let responses: Vec<serde_json::Value> = keys
                .into_iter()
                .map(|(id, name, level, created, last_used)| {
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "permission_level": level,
                        "created_at": created,
                        "last_used_at": last_used,
                    })
                })
                .collect();
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
    db: web::Data<dyn ApiKeyRepo>,
    body: web::Json<GenerateKeyRequest>,
) -> HttpResponse {
    use rand::Rng;
    use rand::distr::Alphanumeric;

    let raw_key: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let key_hash = db.hmac_api_key(&raw_key);

    let level = body.level.as_deref().unwrap_or("read_only");
    if !matches!(level, "read_only" | "read_write" | "full_access") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid permission level. Must be: read_only, read_write, or full_access"
        }));
    }

    match db.insert_api_key(&key_hash, &body.name, level) {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "key": raw_key,
            "name": body.name,
            "permission_level": level,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_key(_auth: AuthClaims, db: web::Data<dyn ApiKeyRepo>, path: web::Path<i64>) -> HttpResponse {
    let id = path.into_inner();
    match db.delete_api_key(id) {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Key not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
