use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder, Scope};
use serde::Deserialize;

use crate::core::auth::jwt::{Claims, JwtService};
use crate::core::auth::password;
use crate::interface::port::repository::RepositoryPort;

type Repo = dyn RepositoryPort;

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

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

pub fn initialize() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/register", web::post().to(register))
        .route("/me", web::get().to(me))
        .route("/change-password", web::post().to(change_password))
}

fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() || username.len() > 32 {
        return Err("Username must be 1-32 characters");
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Username must contain only alphanumeric characters and underscores");
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters");
    }
    Ok(())
}

async fn login(
    body: web::Json<LoginRequest>,
    db: web::Data<Repo>,
    jwt: web::Data<JwtService>,
) -> impl Responder {
    let req = body.into_inner();

    // Check login lockout
    match db.check_login_locked(&req.username) {
        Ok(Some(remaining_secs)) => {
            return HttpResponse::TooManyRequests()
                .json(serde_json::json!({
                    "error": "Account temporarily locked due to too many failed login attempts",
                    "retry_after_secs": remaining_secs,
                }));
        }
        Err(_) => {}
        Ok(None) => {}
    }

    let user = match db.find_user(&req.username) {
        Ok(Some(u)) => u,
        _ => {
            let _ = db.record_login_failure(&req.username);
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid credentials"}));
        }
    };

    let (id, username, hash, role, force_password_change) = user;

    match password::verify_password(&req.password, &hash) {
        Ok(true) => {}
        _ => {
            let _ = db.record_login_failure(&req.username);
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Invalid credentials"}));
        }
    }

    // Clear login failures on success
    let _ = db.clear_login_failures(&req.username);

    match jwt.create_token(id, &username, &role) {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({
            "token": token,
            "role": role,
            "force_password_change": force_password_change,
        })),
        Err(_) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": "Failed to create token"})),
    }
}

async fn register(
    req: HttpRequest,
    body: web::Json<RegisterRequest>,
    db: web::Data<Repo>,
) -> impl Responder {
    // Check caller is admin
    let claims = req.extensions().get::<Claims>().cloned();
    match claims {
        Some(c) if c.role == "admin" => {}
        _ => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "Admin access required"}));
        }
    }

    let reg = body.into_inner();

    // Validate input
    if let Err(msg) = validate_username(&reg.username) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }
    if let Err(msg) = validate_password(&reg.password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }

    // Validate role
    if reg.role != "admin" && reg.role != "viewer" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}));
    }

    let hash = match password::hash_password(&reg.password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    match db.insert_user(&reg.username, &hash, &reg.role, false) {
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

async fn change_password(
    req: HttpRequest,
    body: web::Json<ChangePasswordRequest>,
    db: web::Data<Repo>,
) -> impl Responder {
    let claims = match req.extensions().get::<Claims>().cloned() {
        Some(c) => c,
        None => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Not authenticated"}));
        }
    };

    let change_req = body.into_inner();

    // Validate new password
    if let Err(msg) = validate_password(&change_req.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }

    // Verify current password
    let user = match db.find_user(&claims.username) {
        Ok(Some(u)) => u,
        _ => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "User not found"}));
        }
    };

    let (_id, _username, hash, _role, _force) = user;

    match password::verify_password(&change_req.current_password, &hash) {
        Ok(true) => {}
        _ => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({"error": "Current password is incorrect"}));
        }
    }

    // Hash and update
    let new_hash = match password::hash_password(&change_req.new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    match db.update_user_password(claims.sub, &new_hash) {
        Ok(_) => HttpResponse::Ok()
            .json(serde_json::json!({"message": "Password changed successfully"})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": e.to_string()})),
    }
}
