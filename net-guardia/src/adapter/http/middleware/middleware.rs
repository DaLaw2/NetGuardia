use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{Error as ActixError, HttpMessage, HttpResponse, web};
use macros::log;

use crate::adapter::http::middleware::jwt::JwtService;
use crate::domain::identity::error::AuthError;
use crate::interface::port::api_key::ApiKeyRepo;
use crate::interface::port::app_repo::AppRepo;

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
    let resource = if path == "/api/auth/login" || path == "/api/auth/me" || path == "/api/auth/change-password" {
        return None;
    } else if path.starts_with("/api/auth/") {
        return Some("users:admin".to_string());
    } else if path.starts_with("/api/health/") || path.starts_with("/api/stats/") {
        "dashboard"
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
    } else if path.contains("/soar/blocks/") && path.ends_with("/unblock") {
        return Some("access_control:write".to_string());
    } else if path.starts_with("/api/soar/")
        || path.starts_with("/api/notifications/")
        || path.starts_with("/api/report/")
        || path.starts_with("/api/api-keys/")
        || path.starts_with("/api/logs/")
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

            // Skip auth for public endpoints
            if path == "/api/auth/login" || path.starts_with("/api/setup/") || !path.starts_with("/api/") {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Extract JWT service from app data
            let jwt_service = match req.app_data::<web::Data<JwtService>>() {
                Some(s) => s.clone(),
                None => {
                    let resp =
                        HttpResponse::InternalServerError().json(serde_json::json!({"error": "Auth not configured"}));
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            // Try JWT first, then fall back to API key
            let claims = if let Some(auth_header) = req.headers().get("Authorization") {
                // JWT Bearer token auth
                let val_str = auth_header.to_str().unwrap_or("");
                let token = match val_str.strip_prefix("Bearer ") {
                    Some(t) => t,
                    None => {
                        let resp = HttpResponse::Unauthorized()
                            .json(serde_json::json!({"error": "Invalid authorization header"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                match jwt_service.validate_token(token) {
                    Ok(c) => c,
                    Err(_) => {
                        let resp =
                            HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid or expired token"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            } else if let Some(api_key_header) = req.headers().get("X-API-Key") {
                // API key auth with rate limiting
                let api_key = api_key_header.to_str().unwrap_or("");
                let api_key_port = match req.app_data::<web::Data<dyn ApiKeyRepo>>() {
                    Some(d) => d.clone(),
                    None => {
                        let resp = HttpResponse::InternalServerError()
                            .json(serde_json::json!({"error": "ApiKeyRepo not configured"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };
                let repo = match req.app_data::<web::Data<dyn AppRepo>>() {
                    Some(d) => d.clone(),
                    None => {
                        let resp = HttpResponse::InternalServerError()
                            .json(serde_json::json!({"error": "AppRepo not configured"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                };

                // Rate limit check for API key attempts (reuse login failure tracking)
                let rate_key = format!(
                    "apikey:{}",
                    req.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default()
                );
                if let Ok(Some(remaining)) = repo.check_login_locked(&rate_key) {
                    let resp = HttpResponse::TooManyRequests().json(serde_json::json!({
                        "error": "Too many failed API key attempts",
                        "retry_after_secs": remaining,
                    }));
                    return Ok(req.into_response(resp).map_into_right_body());
                }

                match api_key_port.validate_api_key(api_key) {
                    Ok(Some(key_claims)) => {
                        if let Err(e) = repo.clear_login_failures(&rate_key) {
                            log!(AuthError::LoginClearError(e));
                        }
                        key_claims
                    }
                    Ok(None) => {
                        if let Err(e) = repo.record_login_failure(&rate_key) {
                            log!(AuthError::LoginFailureTrackingError(e));
                        }
                        let resp = HttpResponse::Unauthorized()
                            .json(serde_json::json!({"error": "Invalid or revoked API key"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                    Err(_) => {
                        let resp = HttpResponse::InternalServerError()
                            .json(serde_json::json!({"error": "API key validation failed"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            } else {
                let resp =
                    HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing authorization header"}));
                return Ok(req.into_response(resp).map_into_right_body());
            };

            // Permission-based RBAC check
            if let Some(required) = required_permission(&path, req.method())
                && !claims.permissions.contains(&required)
            {
                let resp = HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
                return Ok(req.into_response(resp).map_into_right_body());
            }

            // Store claims in request extensions
            req.extensions_mut().insert(claims);

            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}
