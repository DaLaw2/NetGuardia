use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{Error as ActixError, HttpResponse, web};

use crate::adapter::http::session::SessionCookieService;
use crate::core::identity::session_service::{CsrfTokenStatus, SessionService};

pub const CSRF_HEADER: &str = "X-CSRF-Token";
const API_KEY_HEADER: &str = "X-API-Key";

pub struct CsrfMiddleware;

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Transform = CsrfMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct CsrfMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
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
        let path = req.path().to_string();
        let method = req.method().clone();
        let has_api_key = req.headers().contains_key(API_KEY_HEADER);
        let csrf_token = req
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);

        Box::pin(async move {
            if should_require_csrf_token(&path, &method, has_api_key) {
                let Some(token) = csrf_token else {
                    let resp = HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "Missing CSRF token",
                        "header": CSRF_HEADER,
                    }));
                    return Ok(req.into_response(resp).map_into_right_body());
                };
                let Some(session_service) = req.app_data::<web::Data<SessionService>>() else {
                    let resp = HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "CSRF validation is not configured",
                    }));
                    return Ok(req.into_response(resp).map_into_right_body());
                };
                let Some(cookie_service) = req.app_data::<web::Data<SessionCookieService>>() else {
                    let resp = HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "CSRF cookie validation is not configured",
                    }));
                    return Ok(req.into_response(resp).map_into_right_body());
                };
                let Some(session_cookie) = req.cookie(cookie_service.cookie_name()) else {
                    let resp = HttpResponse::Forbidden().json(serde_json::json!({
                        "error": "Missing session cookie",
                    }));
                    return Ok(req.into_response(resp).map_into_right_body());
                };
                match session_service.csrf_token_status(session_cookie.value(), &token) {
                    CsrfTokenStatus::Valid => {}
                    CsrfTokenStatus::Expired => {
                        session_service.remove_session(session_cookie.value());
                        let resp = HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "Invalid CSRF token",
                            "header": CSRF_HEADER,
                        }));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                    CsrfTokenStatus::Invalid | CsrfTokenStatus::MissingSession => {
                        let resp = HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "Invalid CSRF token",
                            "header": CSRF_HEADER,
                        }));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
            }
            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

pub fn should_require_csrf_token(path: &str, method: &Method, has_api_key: bool) -> bool {
    !has_api_key && is_state_changing(method) && !is_csrf_exempt_path(path)
}

fn is_state_changing(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn is_csrf_exempt_path(path: &str) -> bool {
    path == "/api/auth/login" || path.starts_with("/api/setup/") || path.starts_with("/ws/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_requests_do_not_need_csrf_token() {
        assert!(!should_require_csrf_token("/api/acl/rules", &Method::GET, false));
        assert!(!should_require_csrf_token("/api/stats/summary", &Method::HEAD, false));
        assert!(!should_require_csrf_token("/api/ml/status", &Method::OPTIONS, false));
    }

    #[test]
    fn state_changing_requests_on_admin_routes_require_csrf_token() {
        assert!(should_require_csrf_token("/api/acl/rules", &Method::POST, false));
        assert!(should_require_csrf_token(
            "/api/ml/models/current",
            &Method::DELETE,
            false
        ));
        assert!(should_require_csrf_token("/api/soar/playbooks/1", &Method::PUT, false));
        assert!(should_require_csrf_token(
            "/api/notifications/telegram",
            &Method::PATCH,
            false
        ));
    }

    #[test]
    fn login_and_setup_are_exempt() {
        assert!(!should_require_csrf_token("/api/auth/login", &Method::POST, false));
        assert!(!should_require_csrf_token(
            "/api/setup/initialize",
            &Method::POST,
            false
        ));
    }

    #[test]
    fn websocket_upgrade_is_exempt() {
        assert!(!should_require_csrf_token("/ws/events", &Method::GET, false));
        assert!(!should_require_csrf_token("/ws/events", &Method::POST, false));
    }

    #[test]
    fn api_key_clients_are_exempt_even_on_state_changing_routes() {
        assert!(!should_require_csrf_token("/api/acl/rules", &Method::POST, true));
        assert!(!should_require_csrf_token("/api/soar/playbooks", &Method::DELETE, true));
    }

    #[test]
    fn api_key_exemption_takes_precedence_over_path_rules() {
        assert!(!should_require_csrf_token("/api/system/reload", &Method::POST, true));
    }
}
