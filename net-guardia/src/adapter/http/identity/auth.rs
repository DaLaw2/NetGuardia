use actix_web::{HttpResponse, Responder, Scope, web};
use serde::Deserialize;

use crate::adapter::http::helpers::ok_or_error;
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::core::identity::auth_service::{AuthService, LoginError, RegisterError};
use crate::domain::identity::auth::{DEFAULT_ADMIN_USERNAME, GROUP_ADMIN, GROUP_VIEWER, ROLE_ADMIN, ROLE_VIEWER};
use crate::domain::identity::password;
use crate::domain::identity::validation::validate_password;
use crate::interface::app_repo::AppRepo;

type Repo = dyn AppRepo;

fn parse_permissions(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or(serde_json::json!([]))
}

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
        .route("/users", web::get().to(list_users))
        .route("/users/{id}", web::delete().to(delete_user))
        .route("/users/{id}/role", web::put().to(update_role))
        .route("/users/{id}/reset-password", web::post().to(reset_password))
        .route("/users/{id}/groups", web::put().to(set_user_groups))
        .route("/groups", web::get().to(list_groups))
        .route("/groups", web::post().to(create_group))
        .route("/groups/{id}", web::get().to(get_group))
        .route("/groups/{id}", web::put().to(update_group))
        .route("/groups/{id}", web::delete().to(delete_group))
}

async fn login(body: web::Json<LoginRequest>, auth_svc: web::Data<AuthService>) -> impl Responder {
    let req = body.into_inner();
    match auth_svc.login(&req.username, &req.password).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(LoginError::Locked { retry_after_secs }) => HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Account temporarily locked due to too many failed login attempts",
            "retry_after_secs": retry_after_secs,
        })),
        Err(LoginError::InvalidCredentials) => {
            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}))
        }
        Err(LoginError::InternalError) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create token"}))
        }
    }
}

async fn register(
    auth: AuthClaims,
    body: web::Json<RegisterRequest>,
    auth_svc: web::Data<AuthService>,
) -> impl Responder {
    let reg = body.into_inner();
    match auth_svc
        .register(&reg.username, &reg.password, &reg.role, &auth.role)
        .await
    {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({"username": reg.username, "role": reg.role})),
        Err(RegisterError::Validation(msg)) => HttpResponse::BadRequest().json(serde_json::json!({"error": msg})),
        Err(RegisterError::InvalidRole) => {
            HttpResponse::BadRequest().json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}))
        }
        Err(RegisterError::Forbidden) => HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "Only administrators can create admin accounts"})),
        Err(RegisterError::HashFailed) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"}))
        }
        Err(RegisterError::Conflict(e)) => HttpResponse::Conflict().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn me(auth: AuthClaims, auth_svc: web::Data<AuthService>) -> impl Responder {
    let profile = auth_svc.user_profile(auth.sub, &auth.username).await;
    HttpResponse::Ok().json(profile)
}

async fn change_password(
    auth: AuthClaims,
    body: web::Json<ChangePasswordRequest>,
    db: web::Data<Repo>,
) -> impl Responder {
    let change_req = body.into_inner();

    if let Err(msg) = validate_password(&change_req.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }

    let user = match db.find_user(&auth.username).await {
        Ok(Some(u)) => u,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "User not found"}));
        }
    };

    match password::verify_password(&change_req.current_password, &user.password_hash) {
        Ok(true) => {}
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Current password is incorrect"}));
        }
    }

    let new_hash = match password::hash_password(&change_req.new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    match db.update_user_password(auth.sub, &new_hash).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Password changed successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_users(_auth: AuthClaims, db: web::Data<Repo>) -> impl Responder {
    match db.list_users_with_groups().await {
        Ok(users) => {
            let result: Vec<serde_json::Value> = users
                .into_iter()
                .map(|u| {
                    let groups: Vec<serde_json::Value> = u
                        .groups
                        .iter()
                        .map(|g| serde_json::json!({"id": g.group_id, "name": g.group_name}))
                        .collect();
                    let role = if u.groups.iter().any(|g| g.group_name == GROUP_ADMIN) {
                        ROLE_ADMIN
                    } else {
                        ROLE_VIEWER
                    };
                    serde_json::json!({
                        "id": u.id,
                        "username": u.username,
                        "role": role,
                        "force_password_change": u.force_password_change,
                        "created_at": u.created_at,
                        "groups": groups,
                    })
                })
                .collect();
            HttpResponse::Ok().json(result)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_user(_auth: AuthClaims, path: web::Path<i64>, db: web::Data<Repo>) -> impl Responder {
    let user_id = path.into_inner();

    if _auth.sub == user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot delete your own account"}));
    }

    match db.find_user_by_id(user_id).await {
        Ok(Some(ref u)) if u.username == DEFAULT_ADMIN_USERNAME => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "Cannot delete the built-in admin account"}));
        }
        _ => {}
    }

    match db.delete_user(user_id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"message": "User deleted successfully"})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn update_role(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    db: web::Data<Repo>,
) -> impl Responder {
    let user_id = path.into_inner();

    if _auth.sub == user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot change your own role"}));
    }

    let role = match body.get("role").and_then(|v| v.as_str()) {
        Some(r) if r == ROLE_ADMIN || r == ROLE_VIEWER => r,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}));
        }
    };

    match db.find_user_by_id(user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }

    match db.update_user_role(user_id, role).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Role updated successfully", "role": role})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn reset_password(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    db: web::Data<Repo>,
) -> impl Responder {
    let user_id = path.into_inner();

    let new_password = match body
        .get("new_password")
        .or_else(|| body.get("password"))
        .and_then(|v| v.as_str())
    {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Password is required"}));
        }
    };

    if let Err(msg) = validate_password(new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }

    match db.find_user_by_id(user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }

    let hash = match password::hash_password(new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    ok_or_error(db.reset_user_password(user_id, &hash).await)
}

async fn list_groups(_auth: AuthClaims, db: web::Data<Repo>) -> impl Responder {
    match db.list_user_groups().await {
        Ok(groups) => {
            let mut result = Vec::with_capacity(groups.len());
            for g in groups {
                let perms: serde_json::Value = parse_permissions(&g.permissions);
                let members: Vec<serde_json::Value> = db
                    .list_group_members(g.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|m| serde_json::json!({"id": m.id, "username": m.username}))
                    .collect();
                result.push(serde_json::json!({
                    "id": g.id,
                    "name": g.name,
                    "description": g.description,
                    "permissions": perms,
                    "created_at": g.created_at,
                    "members": members,
                }));
            }
            HttpResponse::Ok().json(result)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn create_group(_auth: AuthClaims, body: web::Json<serde_json::Value>, db: web::Data<Repo>) -> impl Responder {
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Group name is required"}));
        }
    };

    let description = body.get("description").and_then(|v| v.as_str()).unwrap_or("");
    let permissions = match body.get("permissions") {
        Some(p) if p.is_array() => p.to_string(),
        _ => "[]".to_string(),
    };

    match db.create_user_group(name, description, &permissions).await {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "name": name,
            "description": description,
            "permissions": parse_permissions(&permissions),
        })),
        Err(e) => HttpResponse::Conflict().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_group(_auth: AuthClaims, path: web::Path<i64>, db: web::Data<Repo>) -> impl Responder {
    let group_id = path.into_inner();

    match db.get_user_group(group_id).await {
        Ok(Some(g)) => {
            let perms: serde_json::Value = parse_permissions(&g.permissions);
            let members = db.list_group_member_ids(group_id).await.unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "id": g.id,
                "name": g.name,
                "description": g.description,
                "permissions": perms,
                "created_at": g.created_at,
                "members": members,
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Group not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn update_group(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    db: web::Data<Repo>,
) -> impl Responder {
    let group_id = path.into_inner();

    let existing = match db.get_user_group(group_id).await {
        Ok(Some(g)) => {
            if g.name == GROUP_ADMIN || g.name == GROUP_VIEWER {
                return HttpResponse::Forbidden().json(serde_json::json!({"error": "Cannot modify built-in groups"}));
            }
            g
        }
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Group not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    };

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(&existing.name);
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or(&existing.description);
    let permissions = match body.get("permissions") {
        Some(p) if p.is_array() => p.to_string(),
        _ => existing.permissions.clone(),
    };

    match db.update_user_group(group_id, name, description, &permissions).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "id": group_id,
            "name": name,
            "description": description,
            "permissions": parse_permissions(&permissions),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_group(_auth: AuthClaims, path: web::Path<i64>, db: web::Data<Repo>) -> impl Responder {
    let group_id = path.into_inner();

    match db.get_user_group(group_id).await {
        Ok(Some(ref g)) if g.name == GROUP_ADMIN || g.name == GROUP_VIEWER => {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "Cannot delete built-in groups"}));
        }
        _ => {}
    }

    match db.delete_user_group(group_id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({"message": "Group deleted successfully"})),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": "Group not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn set_user_groups(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<serde_json::Value>,
    db: web::Data<Repo>,
) -> impl Responder {
    let user_id = path.into_inner();

    match db.find_user_by_id(user_id).await {
        Ok(Some(ref u)) if u.username == DEFAULT_ADMIN_USERNAME => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "Cannot modify groups for the built-in admin account"}));
        }
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }

    let group_ids: Vec<i64> = match body.get("group_ids").and_then(|v| v.as_array()) {
        Some(arr) => arr.iter().filter_map(|v| v.as_i64()).collect(),
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "group_ids array is required"}));
        }
    };

    match db.set_user_groups(user_id, &group_ids).await {
        Ok(_) => HttpResponse::Ok()
            .json(serde_json::json!({"message": "User groups updated successfully", "group_ids": group_ids})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::identity::validation::{validate_password, validate_username};

    #[test]
    fn test_dummy_hash_is_valid_argon2() {
        use argon2::password_hash::PasswordHash;

        use crate::core::identity::auth_service::DUMMY_HASH;
        let parsed = PasswordHash::new(DUMMY_HASH);
        assert!(
            parsed.is_ok(),
            "DUMMY_HASH should be a valid Argon2 hash format, got error: {:?}",
            parsed.err()
        );
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("user_123").is_ok());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("12345678").is_ok());
    }
}
