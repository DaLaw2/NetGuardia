use actix_web::http::{StatusCode, header};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, Responder, Scope, web};
use serde::{Deserialize, Serialize};

use crate::adapter::http::helpers::{bad_request, conflict, forbidden, internal_error, json_error, not_found};
use crate::adapter::http::middleware::extractor::AuthClaims;
use crate::adapter::http::session::SessionCookieService;
use crate::core::identity::auth_service::AuthService;
use crate::core::identity::group_service::GroupService;
use crate::core::identity::session_service::SessionService;
use crate::core::identity::user_service::{UserProfile, UserService};
use crate::domain::identity::auth::{Claims, ROLE_ADMIN, ROLE_VIEWER};
use crate::domain::identity::error::{GroupError, LoginError, RegisterError, UserError};

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

#[derive(Deserialize)]
struct UpdateRoleRequest {
    role: String,
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    new_password: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct SetUserGroupsRequest {
    group_ids: Vec<i64>,
}

#[derive(Serialize)]
struct MeResponse {
    id: i64,
    username: String,
    role: String,
    permissions: Vec<String>,
    groups: Vec<String>,
    csrf_token: Option<String>,
}

impl MeResponse {
    fn from_profile(profile: UserProfile, csrf_token: Option<String>) -> Self {
        Self {
            id: profile.id,
            username: profile.username,
            role: profile.role,
            permissions: profile.permissions,
            groups: profile.groups,
            csrf_token,
        }
    }
}

fn append_session_removal_cookies(response: &mut HttpResponseBuilder, cookie_service: &SessionCookieService) {
    for cookie in cookie_service.removal_cookies() {
        response.append_header((header::SET_COOKIE, cookie.to_string()));
    }
}

async fn invalidate_group_member_sessions(group_svc: &GroupService, session_service: &SessionService, group_id: i64) {
    if let Ok(Some(group)) = group_svc.get_group(group_id).await {
        for user_id in group.members {
            session_service.remove_sessions_for_user(user_id);
        }
    }
}

async fn group_member_ids(group_svc: &GroupService, group_id: i64) -> Vec<i64> {
    match group_svc.get_group(group_id).await {
        Ok(Some(group)) => group.members,
        _ => Vec::new(),
    }
}

pub fn initialize() -> Scope {
    web::scope("/auth")
        .route("/login", web::post().to(login))
        .route("/logout", web::post().to(logout))
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

async fn login(
    body: web::Json<LoginRequest>,
    auth_svc: web::Data<AuthService>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    let req = body.into_inner();
    match auth_svc.login(&req.username, &req.password).await {
        Ok(result) => {
            let claims = Claims {
                sub: result.user_id,
                username: result.username,
                role: result.role.clone(),
                permissions: result.permissions,
            };
            let session = session_service.create_session(claims);
            HttpResponse::Ok()
                .append_header((header::SET_COOKIE, cookie_service.session_cookie(&session).to_string()))
                .json(serde_json::json!({
                    "role": result.role,
                    "force_password_change": result.force_password_change,
                    "csrf_token": session.csrf_token,
                }))
        }
        Err(LoginError::Locked { retry_after_secs }) => HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Account temporarily locked due to too many failed login attempts",
            "retry_after_secs": retry_after_secs,
        })),
        Err(LoginError::InvalidCredentials) => json_error(StatusCode::UNAUTHORIZED, "Invalid credentials"),
        Err(LoginError::InternalError) => internal_error("Failed to login"),
    }
}

async fn logout(
    req: HttpRequest,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    if let Some(cookie) = req.cookie(cookie_service.cookie_name()) {
        session_service.remove_session(cookie.value());
    }

    let mut response = HttpResponse::Ok();
    append_session_removal_cookies(&mut response, &cookie_service);
    response.json(serde_json::json!({"message": "Logged out"}))
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
        Err(e @ RegisterError::Validation { .. }) => bad_request(e.to_string()),
        Err(RegisterError::InvalidRole) => bad_request("Role must be 'admin' or 'viewer'"),
        Err(RegisterError::Forbidden) => forbidden("Only administrators can create admin accounts"),
        Err(RegisterError::HashFailed) => internal_error("Failed to hash password"),
        Err(e @ RegisterError::Conflict { .. }) => conflict(e.to_string()),
        Err(e @ RegisterError::Internal { .. }) => internal_error(e.to_string()),
    }
}

async fn me(
    req: HttpRequest,
    auth: AuthClaims,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    match user_svc.user_profile(auth.sub, &auth.username).await {
        Ok(profile) => {
            let csrf_token = req
                .cookie(cookie_service.cookie_name())
                .and_then(|cookie| session_service.csrf_token_for_session(cookie.value()));
            HttpResponse::Ok().json(MeResponse::from_profile(profile, csrf_token))
        }
        Err(e) => internal_error(e),
    }
}

async fn change_password(
    auth: AuthClaims,
    body: web::Json<ChangePasswordRequest>,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    let change_req = body.into_inner();

    match user_svc
        .change_password(auth.sub, &change_req.current_password, &change_req.new_password)
        .await
    {
        Ok(()) => {
            session_service.remove_sessions_for_user(auth.sub);
            let mut response = HttpResponse::Ok();
            append_session_removal_cookies(&mut response, &cookie_service);
            response.json(serde_json::json!({"message": "Password changed successfully"}))
        }
        Err(e) => user_error(e),
    }
}

async fn list_users(_auth: AuthClaims, user_svc: web::Data<UserService>) -> impl Responder {
    match user_svc.list_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => internal_error(e),
    }
}

async fn delete_user(
    auth: AuthClaims,
    path: web::Path<i64>,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    let user_id = path.into_inner();

    match user_svc.delete_user(auth.sub, user_id).await {
        Ok(true) => {
            session_service.remove_sessions_for_user(user_id);
            HttpResponse::Ok().json(serde_json::json!({"message": "User deleted successfully"}))
        }
        Ok(false) => not_found("User not found"),
        Err(e) => user_error(e),
    }
}

async fn update_role(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<UpdateRoleRequest>,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    let user_id = path.into_inner();
    let req = body.into_inner();

    if req.role != ROLE_ADMIN && req.role != ROLE_VIEWER {
        return bad_request("Role must be 'admin' or 'viewer'");
    }

    match user_svc.update_role(_auth.sub, user_id, &req.role).await {
        Ok(_) => {
            session_service.remove_sessions_for_user(user_id);
            HttpResponse::Ok().json(serde_json::json!({"message": "Role updated successfully", "role": req.role}))
        }
        Err(e) => user_error(e),
    }
}

async fn reset_password(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<ResetPasswordRequest>,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
    cookie_service: web::Data<SessionCookieService>,
) -> impl Responder {
    let user_id = path.into_inner();
    let req = body.into_inner();

    let new_password = match req.new_password.as_deref().or(req.password.as_deref()) {
        Some(p) => p,
        None => {
            return bad_request("Password is required");
        }
    };

    match user_svc.reset_password(user_id, new_password).await {
        Ok(()) => {
            session_service.remove_sessions_for_user(user_id);
            let mut response = HttpResponse::Ok();
            if user_id == _auth.sub {
                append_session_removal_cookies(&mut response, &cookie_service);
            }
            response.finish()
        }
        Err(e) => user_error(e),
    }
}

fn user_error(err: UserError) -> HttpResponse {
    match err {
        UserError::Validation { .. } => bad_request(err.to_string()),
        UserError::Unauthorized => json_error(StatusCode::UNAUTHORIZED, "Current password is incorrect"),
        UserError::Forbidden { .. } => forbidden(err.to_string()),
        UserError::NotFound { .. } => not_found(err.to_string()),
        UserError::HashFailed => internal_error("Failed to hash password"),
        UserError::Conflict { .. } => conflict(err.to_string()),
        UserError::Internal { .. } => internal_error(err.to_string()),
    }
}

fn group_error(err: GroupError) -> HttpResponse {
    match err {
        GroupError::Validation { .. } => bad_request(err.to_string()),
        GroupError::Forbidden { .. } => forbidden(err.to_string()),
        GroupError::NotFound { .. } => not_found(err.to_string()),
        GroupError::Conflict { .. } => conflict(err.to_string()),
        GroupError::Internal { .. } => internal_error(err.to_string()),
    }
}

async fn list_groups(_auth: AuthClaims, group_svc: web::Data<GroupService>) -> impl Responder {
    match group_svc.list_groups().await {
        Ok(groups) => HttpResponse::Ok().json(groups),
        Err(e) => internal_error(e),
    }
}

async fn create_group(
    _auth: AuthClaims,
    body: web::Json<CreateGroupRequest>,
    group_svc: web::Data<GroupService>,
) -> impl Responder {
    let req = body.into_inner();
    match group_svc
        .create_group(
            req.name.as_deref(),
            req.description.as_deref(),
            req.permissions.as_ref(),
        )
        .await
    {
        Ok(group) => HttpResponse::Created().json(group),
        Err(e) => group_error(e),
    }
}

async fn get_group(_auth: AuthClaims, path: web::Path<i64>, group_svc: web::Data<GroupService>) -> impl Responder {
    let group_id = path.into_inner();

    match group_svc.get_group(group_id).await {
        Ok(Some(group)) => HttpResponse::Ok().json(group),
        Ok(None) => not_found("Group not found"),
        Err(e) => internal_error(e),
    }
}

async fn update_group(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<UpdateGroupRequest>,
    group_svc: web::Data<GroupService>,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    let group_id = path.into_inner();
    let req = body.into_inner();

    match group_svc
        .update_group(
            group_id,
            req.name.as_deref(),
            req.description.as_deref(),
            req.permissions.as_ref(),
        )
        .await
    {
        Ok(group) => {
            invalidate_group_member_sessions(&group_svc, &session_service, group_id).await;
            HttpResponse::Ok().json(group)
        }
        Err(e) => group_error(e),
    }
}

async fn delete_group(
    _auth: AuthClaims,
    path: web::Path<i64>,
    group_svc: web::Data<GroupService>,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    let group_id = path.into_inner();
    let member_ids = group_member_ids(&group_svc, group_id).await;

    match group_svc.delete_group(group_id).await {
        Ok(true) => {
            for user_id in member_ids {
                session_service.remove_sessions_for_user(user_id);
            }
            HttpResponse::Ok().json(serde_json::json!({"message": "Group deleted successfully"}))
        }
        Ok(false) => not_found("Group not found"),
        Err(e) => group_error(e),
    }
}

async fn set_user_groups(
    _auth: AuthClaims,
    path: web::Path<i64>,
    body: web::Json<SetUserGroupsRequest>,
    user_svc: web::Data<UserService>,
    session_service: web::Data<SessionService>,
) -> impl Responder {
    let user_id = path.into_inner();
    let req = body.into_inner();

    match user_svc.set_user_groups(_auth.sub, user_id, &req.group_ids).await {
        Ok(_) => {
            session_service.remove_sessions_for_user(user_id);
            HttpResponse::Ok()
                .json(serde_json::json!({"message": "User groups updated successfully", "group_ids": req.group_ids}))
        }
        Err(e) => user_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::SetUserGroupsRequest;
    use crate::core::identity::user_service::parse_permissions;
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
    fn parse_permissions_rejects_invalid_json() {
        let err = parse_permissions("{bad json").expect_err("invalid permissions JSON should fail");

        assert!(err.to_string().contains("deserialize"));
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("user_123").is_ok());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("Password1!").is_ok());
    }

    #[test]
    fn set_user_groups_request_rejects_malformed_entries() {
        let body = serde_json::json!({
            "group_ids": [1, "2", null]
        });

        let result: Result<SetUserGroupsRequest, _> = serde_json::from_value(body);

        assert!(result.is_err());
    }

    #[test]
    fn set_user_groups_request_accepts_integer_entries() {
        let body = serde_json::json!({
            "group_ids": [1, 2, 3]
        });

        let req: SetUserGroupsRequest = serde_json::from_value(body).expect("valid group ids");

        assert_eq!(req.group_ids, vec![1, 2, 3]);
    }
}
