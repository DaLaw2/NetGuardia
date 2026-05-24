use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::{Method, StatusCode};
use actix_web::{Error as ActixError, HttpMessage, HttpResponse, web};
use macros::log;

use crate::adapter::http::helpers::json_error;
use crate::adapter::http::session::SessionCookieService;
use crate::core::identity::session_service::SessionService;
use crate::domain::common::config::constants::{
    PERMISSION_ACCESS_CONTROL_WRITE, PERMISSION_API_KEYS_ADMIN, PERMISSION_USERS_ADMIN,
};
use crate::domain::identity::error::AuthError;
use crate::interface::identity::api_key::ApiKeyRepo;
use crate::interface::identity::api_key_hasher::ApiKeyHasher;
use crate::interface::identity::auth_repo::LoginAttemptRepo;

pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
}

fn required_permission(path: &str, method: &Method) -> Option<String> {
    let resource = if path == "/api/auth/login"
        || path == "/api/auth/logout"
        || path == "/api/auth/me"
        || path == "/api/auth/change-password"
    {
        return None;
    } else if path.starts_with("/api/auth/") {
        return Some(PERMISSION_USERS_ADMIN.to_string());
    } else if path.starts_with("/api/health/") {
        "dashboard"
    } else if path.starts_with("/api/stats/drops") {
        "drops"
    } else if path.starts_with("/api/stats/flows") {
        "traffic_map"
    } else if path.starts_with("/api/stats/summary") {
        "statistics"
    } else if path.starts_with("/api/ml/") || path.starts_with("/api/byo/") {
        "ai_detection"
    } else if path.starts_with("/api/fusion/") {
        "fusion"
    } else if path.starts_with("/api/flow-trace/") {
        "flow_trace"
    } else if path.starts_with("/api/acl/geo/") {
        "geo_block"
    } else if path.starts_with("/api/acl/") {
        "access_control"
    } else if path.starts_with("/api/filter/dns/") {
        "dns_filter"
    } else if path.starts_with("/api/filter/http/") || path.starts_with("/api/filter/ssh/") {
        "protocol_filter"
    } else if path.starts_with("/api/rate-limit/") {
        "rate_limit"
    } else if path.starts_with("/api/system/") {
        "system"
    } else if path == "/api/api-keys" || path.starts_with("/api/api-keys/") {
        return Some(PERMISSION_API_KEYS_ADMIN.to_string());
    } else if path.contains("/soar/blocks/") && path.ends_with("/unblock") {
        return Some(PERMISSION_ACCESS_CONTROL_WRITE.to_string());
    } else if path.starts_with("/api/soar/")
        || path.starts_with("/api/notifications/")
        || path == "/api/report"
        || path.starts_with("/api/report/")
        || path == "/api/logs"
        || path.starts_with("/api/logs/")
        || path == "/api/audit"
        || path.starts_with("/api/audit/")
    {
        "system"
    } else {
        return None;
    };

    let action = match *method {
        Method::GET => "read",
        _ => "write",
    };

    Some(format!("{}:{}", resource, action))
}

fn is_auth_exempt_request(path: &str, method: &Method) -> bool {
    *method == Method::OPTIONS
        || path == "/api/auth/login"
        || path.starts_with("/api/setup/")
        || !path.starts_with("/api/")
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let path = req.path().to_string();

            if is_auth_exempt_request(&path, req.method()) {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            let claims = if let Some(api_key_header) = req.headers().get("X-API-Key") {
                let api_key = api_key_header.to_str().unwrap_or("");
                let api_key_port = match req.app_data::<web::Data<dyn ApiKeyRepo>>() {
                    Some(d) => d.clone(),
                    None => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "ApiKeyRepo not configured");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                let api_key_hasher = match req.app_data::<web::Data<dyn ApiKeyHasher>>() {
                    Some(d) => d.clone(),
                    None => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "ApiKeyHasher not configured");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                let login_attempt_repo = match req.app_data::<web::Data<dyn LoginAttemptRepo>>() {
                    Some(d) => d.clone(),
                    None => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "LoginAttemptRepo not configured");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };

                let rate_key = format!(
                    "apikey:{}",
                    req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default()
                );
                match login_attempt_repo.get_remaining_lock_secs(&rate_key).await {
                    Ok(Some(remaining)) => {
                        let resp = HttpResponse::TooManyRequests().json(serde_json::json!({
                            "error": "Too many failed API key attempts",
                            "retry_after_secs": remaining,
                        }));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                    Ok(None) => {
                        if let Err(e) = login_attempt_repo.clear_expired_login_lock(&rate_key).await {
                            log!(AuthError::LoginLockoutLookupFailed(e));
                            let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "API key lockout cleanup failed");
                            return Ok(req.into_response(resp).map_into_right_body());
                        }
                    }
                    Err(e) => {
                        log!(AuthError::LoginLockoutLookupFailed(e));
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "API key lockout check failed");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }

                let key_hash = api_key_hasher.hash_api_key(api_key);
                match api_key_port.validate_api_key(&key_hash).await {
                    Ok(Some(key_claims)) => {
                        if let Err(e) = login_attempt_repo.clear_login_failures(&rate_key).await {
                            log!(AuthError::LoginClearError(e));
                        }
                        key_claims
                    }
                    Ok(None) => {
                        if let Err(e) = login_attempt_repo.record_login_failure(&rate_key).await {
                            log!(AuthError::LoginFailureTrackingError(e));
                        }
                        let resp = json_error(StatusCode::UNAUTHORIZED, "Invalid or revoked API key");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                    Err(_) => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "API key validation failed");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            } else {
                let session_service = match req.app_data::<web::Data<SessionService>>() {
                    Some(service) => service.clone(),
                    None => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "Session auth not configured");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                let cookie_service = match req.app_data::<web::Data<SessionCookieService>>() {
                    Some(service) => service.clone(),
                    None => {
                        let resp = json_error(StatusCode::INTERNAL_SERVER_ERROR, "Session cookie auth not configured");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                let Some(session_cookie) = req.cookie(cookie_service.cookie_name()) else {
                    let resp = json_error(StatusCode::UNAUTHORIZED, "Missing authentication cookie");
                    return Ok(req.into_response(resp).map_into_right_body());
                };
                match session_service.claims_for_session(session_cookie.value()) {
                    Some(claims) => claims,
                    None => {
                        let resp = json_error(StatusCode::UNAUTHORIZED, "Invalid or expired session");
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            };

            if let Some(required) = required_permission(&path, req.method())
                && !claims.permissions.contains(&required)
            {
                let resp = json_error(StatusCode::FORBIDDEN, "Insufficient permissions");
                return Ok(req.into_response(resp).map_into_right_body());
            }

            req.extensions_mut().insert(claims);

            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::Method;

    use super::{is_auth_exempt_request, required_permission};

    #[test]
    fn api_key_collection_requires_admin_permission() {
        assert_eq!(
            required_permission("/api/api-keys", &Method::GET),
            Some("api_keys:admin".to_string())
        );
    }

    #[test]
    fn api_key_subroutes_require_admin_permission() {
        assert_eq!(
            required_permission("/api/api-keys/generate", &Method::POST),
            Some("api_keys:admin".to_string())
        );
        assert_eq!(
            required_permission("/api/api-keys/1", &Method::DELETE),
            Some("api_keys:admin".to_string())
        );
    }

    #[test]
    fn password_change_routes_do_not_require_feature_permissions() {
        assert_eq!(required_permission("/api/auth/me", &Method::GET), None);
        assert_eq!(required_permission("/api/auth/change-password", &Method::POST), None);
    }

    #[test]
    fn stats_routes_use_specific_read_permissions() {
        assert_eq!(
            required_permission("/api/stats/summary", &Method::GET),
            Some("statistics:read".to_string())
        );
        assert_eq!(
            required_permission("/api/stats/flows", &Method::GET),
            Some("traffic_map:read".to_string())
        );
        assert_eq!(
            required_permission("/api/stats/flows/top/10", &Method::GET),
            Some("traffic_map:read".to_string())
        );
        assert_eq!(
            required_permission("/api/stats/drops", &Method::GET),
            Some("drops:read".to_string())
        );
    }

    #[test]
    fn collection_endpoints_require_system_permissions() {
        assert_eq!(
            required_permission("/api/logs", &Method::GET),
            Some("system:read".to_string())
        );
        assert_eq!(
            required_permission("/api/audit", &Method::GET),
            Some("system:read".to_string())
        );
        assert_eq!(
            required_permission("/api/report/data", &Method::GET),
            Some("system:read".to_string())
        );
        assert_eq!(
            required_permission("/api/report/generate", &Method::POST),
            Some("system:write".to_string())
        );
    }

    #[test]
    fn options_requests_are_auth_exempt_preflight() {
        assert!(is_auth_exempt_request("/api/acl/rules", &Method::OPTIONS));
        assert!(is_auth_exempt_request("/api/report/generate", &Method::OPTIONS));
    }
}
