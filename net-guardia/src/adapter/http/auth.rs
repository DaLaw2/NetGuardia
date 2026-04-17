use actix_web::{HttpResponse, Responder, Scope, web};
use macros::log;
use serde::Deserialize;

use crate::core::auth::extractor::AuthClaims;
use crate::core::auth::jwt::JwtService;
use crate::core::auth::password;
use crate::interface::port::app_repo::AppRepo;
use crate::model::error::auth::AuthError;

type Repo = dyn AppRepo;

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

/// Dummy Argon2 hash used to prevent timing-based username enumeration.
/// When a user doesn't exist, we still run verify_password against this
/// so the response time is indistinguishable from a real user lookup.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$dW5rbm93bg$QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";

async fn login(body: web::Json<LoginRequest>, db: web::Data<Repo>, jwt: web::Data<JwtService>) -> impl Responder {
    let req = body.into_inner();

    // Check login lockout
    match db.check_login_locked(&req.username) {
        Ok(Some(remaining_secs)) => {
            return HttpResponse::TooManyRequests().json(serde_json::json!({
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
            // Run dummy hash verification to prevent timing-based username enumeration
            let _ = password::verify_password(&req.password, DUMMY_HASH);
            if let Err(e) = db.record_login_failure(&req.username) {
                log!(AuthError::LoginFailureTrackingError(e));
            }
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
        }
    };

    let (id, username, hash, _db_role, force_password_change) = user;

    match password::verify_password(&req.password, &hash) {
        Ok(true) => {}
        _ => {
            if let Err(e) = db.record_login_failure(&req.username) {
                log!(AuthError::LoginFailureTrackingError(e));
            }
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
        }
    }

    // Clear login failures on success
    if let Err(e) = db.clear_login_failures(&req.username) {
        log!(AuthError::LoginClearError(e));
    }

    // Permissions come exclusively from groups — no role-based fallback
    let permissions = db.get_user_permissions(id).unwrap_or_default();

    let groups = db.get_user_groups(id).unwrap_or_default();
    let role = if groups.iter().any(|(_id, name, _desc, _perms)| name == "Administrator") {
        "admin".to_string()
    } else {
        "viewer".to_string()
    };

    match jwt.create_token(id, &username, &role, permissions) {
        Ok(token) => HttpResponse::Ok().json(serde_json::json!({
            "token": token,
            "role": role,
            "force_password_change": force_password_change,
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to create token"})),
    }
}

async fn register(auth: AuthClaims, body: web::Json<RegisterRequest>, db: web::Data<Repo>) -> impl Responder {
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
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}));
    }

    // Only admins can create admin accounts
    if reg.role == "admin" && auth.role != "admin" {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({"error": "Only administrators can create admin accounts"}));
    }

    let hash = match password::hash_password(&reg.password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    match db.insert_user(&reg.username, &hash, &reg.role, false) {
        Ok(new_user_id) => {
            // Auto-assign to default group based on role
            let default_group_name = if reg.role == "admin" { "Administrator" } else { "Viewer" };
            if let Ok(groups) = db.list_user_groups()
                && let Some((group_id, _, _, _, _)) =
                    groups.into_iter().find(|(_, name, _, _, _)| name == default_group_name)
                && let Err(e) = db.set_user_groups(new_user_id, &[group_id])
            {
                log!(AuthError::GroupAssignmentFailed(e));
            }
            HttpResponse::Created().json(serde_json::json!({"username": reg.username, "role": reg.role}))
        }
        Err(e) => HttpResponse::Conflict().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn me(auth: AuthClaims, db: web::Data<Repo>) -> impl Responder {
    let user_groups = db.get_user_groups(auth.sub).unwrap_or_default();
    let group_names: Vec<String> = user_groups
        .iter()
        .map(|(_id, name, _desc, _perms)| name.clone())
        .collect();
    let role = if group_names.iter().any(|n| n == "Administrator") {
        "admin"
    } else {
        "viewer"
    };
    let permissions = db.get_user_permissions(auth.sub).unwrap_or_default();
    HttpResponse::Ok().json(serde_json::json!({
        "id": auth.sub,
        "username": auth.username,
        "role": role,
        "permissions": permissions,
        "groups": group_names,
    }))
}

async fn change_password(
    auth: AuthClaims,
    body: web::Json<ChangePasswordRequest>,
    db: web::Data<Repo>,
) -> impl Responder {
    let claims = &*auth;
    let change_req = body.into_inner();

    // Validate new password
    if let Err(msg) = validate_password(&change_req.new_password) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": msg}));
    }

    // Verify current password
    let user = match db.find_user(&claims.username) {
        Ok(Some(u)) => u,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "User not found"}));
        }
    };

    let (_id, _username, hash, _role, _force) = user;

    match password::verify_password(&change_req.current_password, &hash) {
        Ok(true) => {}
        _ => {
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Current password is incorrect"}));
        }
    }

    // Hash and update
    let new_hash = match password::hash_password(&change_req.new_password) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"}));
        }
    };

    match db.update_user_password(claims.sub, &new_hash) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Password changed successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// --- User Management (admin only) ---

async fn list_users(_auth: AuthClaims, db: web::Data<Repo>) -> impl Responder {
    match db.list_users_with_groups() {
        Ok(users) => {
            let result: Vec<serde_json::Value> = users
                .into_iter()
                .map(|(id, username, _role, force_pw, created_at, user_groups)| {
                    let groups: Vec<serde_json::Value> = user_groups
                        .iter()
                        .map(|(gid, name)| serde_json::json!({"id": gid, "name": name}))
                        .collect();
                    let role = if user_groups.iter().any(|(_id, name)| name == "Administrator") {
                        "admin"
                    } else {
                        "viewer"
                    };
                    serde_json::json!({
                        "id": id,
                        "username": username,
                        "role": role,
                        "force_password_change": force_pw,
                        "created_at": created_at,
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

    // Can't delete self
    if _auth.sub == user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot delete your own account"}));
    }

    // Protect the built-in admin account
    match db.find_user_by_id(user_id) {
        Ok(Some((_, ref username, _, _, _))) if username == "admin" => {
            return HttpResponse::Forbidden()
                .json(serde_json::json!({"error": "Cannot delete the built-in admin account"}));
        }
        _ => {}
    }

    match db.delete_user(user_id) {
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

    // Can't change own role
    if _auth.sub == user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot change your own role"}));
    }

    let role = match body.get("role").and_then(|v| v.as_str()) {
        Some(r) if r == "admin" || r == "viewer" => r,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Role must be 'admin' or 'viewer'"}));
        }
    };

    // Check target user exists
    match db.find_user_by_id(user_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    }

    match db.update_user_role(user_id, role) {
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

    // Check target user exists
    match db.find_user_by_id(user_id) {
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

    match db.reset_user_password(user_id, &hash) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"message": "Password reset successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// --- User Group Management (users:admin required) ---

async fn list_groups(_auth: AuthClaims, db: web::Data<Repo>) -> impl Responder {
    match db.list_user_groups() {
        Ok(groups) => {
            let result: Vec<serde_json::Value> = groups
                .into_iter()
                .map(|(id, name, description, permissions, created_at)| {
                    let perms: serde_json::Value = serde_json::from_str(&permissions).unwrap_or(serde_json::json!([]));
                    let members: Vec<serde_json::Value> = db
                        .get_group_members(id)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(uid, username)| serde_json::json!({"id": uid, "username": username}))
                        .collect();
                    serde_json::json!({
                        "id": id,
                        "name": name,
                        "description": description,
                        "permissions": perms,
                        "created_at": created_at,
                        "members": members,
                    })
                })
                .collect();
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

    match db.create_user_group(name, description, &permissions) {
        Ok(id) => HttpResponse::Created().json(serde_json::json!({
            "id": id,
            "name": name,
            "description": description,
            "permissions": serde_json::from_str::<serde_json::Value>(&permissions).unwrap_or(serde_json::json!([])),
        })),
        Err(e) => HttpResponse::Conflict().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_group(_auth: AuthClaims, path: web::Path<i64>, db: web::Data<Repo>) -> impl Responder {
    let group_id = path.into_inner();

    match db.get_user_group(group_id) {
        Ok(Some((id, name, description, permissions, created_at))) => {
            let perms: serde_json::Value = serde_json::from_str(&permissions).unwrap_or(serde_json::json!([]));
            let members = db.get_group_member_ids(group_id).unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "id": id,
                "name": name,
                "description": description,
                "permissions": perms,
                "created_at": created_at,
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

    // Check group exists
    let existing = match db.get_user_group(group_id) {
        Ok(Some(g)) => {
            // Protect built-in groups
            if g.1 == "Administrator" || g.1 == "Viewer" {
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

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(&existing.1);
    let description = body.get("description").and_then(|v| v.as_str()).unwrap_or(&existing.2);
    let permissions = match body.get("permissions") {
        Some(p) if p.is_array() => p.to_string(),
        _ => existing.3.clone(),
    };

    match db.update_user_group(group_id, name, description, &permissions) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "id": group_id,
            "name": name,
            "description": description,
            "permissions": serde_json::from_str::<serde_json::Value>(&permissions).unwrap_or(serde_json::json!([])),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn delete_group(_auth: AuthClaims, path: web::Path<i64>, db: web::Data<Repo>) -> impl Responder {
    let group_id = path.into_inner();

    // Protect built-in groups
    match db.get_user_group(group_id) {
        Ok(Some(g)) if g.1 == "Administrator" || g.1 == "Viewer" => {
            return HttpResponse::Forbidden().json(serde_json::json!({"error": "Cannot delete built-in groups"}));
        }
        _ => {}
    }

    match db.delete_user_group(group_id) {
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

    // Protect the default admin account
    match db.find_user_by_id(user_id) {
        Ok(Some((_, ref username, _, _, _))) if username == "admin" => {
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

    match db.set_user_groups(user_id, &group_ids) {
        Ok(_) => HttpResponse::Ok()
            .json(serde_json::json!({"message": "User groups updated successfully", "group_ids": group_ids})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("user_123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn test_validate_username_empty() {
        assert!(validate_username("").is_err());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = "a".repeat(33);
        assert!(validate_username(&long).is_err());
    }

    #[test]
    fn test_validate_username_special_chars() {
        assert!(validate_username("admin@host").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user-name").is_err());
        assert!(validate_username("用戶").is_err());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a very long password").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("a").is_err());
    }

    #[test]
    fn test_dummy_hash_is_valid_argon2() {
        use argon2::password_hash::PasswordHash;
        // DUMMY_HASH must be parseable as a valid Argon2 hash structure
        // so that timing-based username enumeration is prevented
        let parsed = PasswordHash::new(DUMMY_HASH);
        assert!(
            parsed.is_ok(),
            "DUMMY_HASH should be a valid Argon2 hash format, got error: {:?}",
            parsed.err()
        );
    }
}
