use actix_web::{web, HttpRequest, HttpResponse, Responder, Scope};
use serde::Deserialize;

use crate::core::auth::jwt::{Claims, JwtService};
use crate::core::auth::password;
use crate::core::database::Database;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    role: String,
}

pub fn initialize() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/me", web::get().to(me))
}

async fn login(
    body: web::Json<LoginRequest>,
    db: web::Data<Database>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    let req = body.into_inner();

    let user = match db.find_user(&req.username) {
        Ok(Some(u)) => u,
        _ => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid credentials"}))
        }
    };

    let (id, username, hash, role) = user;

    match password::verify_password(&req.password, &hash) {
        Ok(true) => {}
        _ => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid credentials"}))
        }
    }

    match jwt.create_token(id, &username, &role) {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({
            "token": token,
            "role": role,
        })),
        Err(_) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "Failed to create token"})),
    }
}

async fn register(
    req: HttpRequest,
    body: web::Json<RegisterRequest>,
    db: web::Data<Database>,
) -> impl Responder {
    // Check caller is admin
    let claims = req.extensions().get::<Claims>().cloned();
    match claims {
        Some(c) if c.role == "admin" => {}
        _ => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "Admin access required"}))
        }
    }

    let reg = body.into_inner();

    // Validate role
    if reg.role != "admin" && reg.role != "viewer" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}));
    }

    let hash = match password::hash_password(&reg.password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to hash password"}))
        }
    };

    match db.insert_user(&reg.username, &hash, &reg.role) {
        Ok(_) => HttpResponse::Created()
            .json(serde_json::json!({"username": reg.username, "role": reg.role})),
        Err(e) => {
            HttpResponse::Conflict().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

async fn me(req: HttpRequest) -> impl Responder {
    match req.extensions().get::<Claims>().cloned() {
        Some(claims) => HttpResponse::Ok().json(serde_json::json!({
            "id": claims.sub,
            "username": claims.username,
            "role": claims.role,
        })),
        None => HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Not authenticated"})),
    }
}
