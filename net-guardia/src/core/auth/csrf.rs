//! CSRF defense-in-depth middleware.
//!
//! The primary auth path uses `Authorization: Bearer <jwt>` — a scheme
//! the browser never auto-attaches — so classical CSRF against a
//! malicious same-origin form POST is already neutralized. This
//! middleware adds a belt-and-suspenders layer on top:
//!
//! - State-changing requests (anything that isn't `GET`/`HEAD`/`OPTIONS`)
//!   must carry an `X-CSRF-Token` header.
//! - The header's presence alone is the check. Cross-origin attackers
//!   cannot set custom request headers on simple requests (browsers
//!   block that via the CORS preflight), so a successful request from
//!   a third-party page would need to run JS inside our origin, at
//!   which point CSRF is the wrong threat label anyway.
//! - Exempt: auth / setup bootstrap endpoints (no session yet),
//!   WebSocket upgrade (no body to forge), and `X-API-Key`
//!   authentication (sealed credential — the request isn't a browser
//!   navigation at all).
//!
//! The decision lives in `should_require_csrf_token` so unit tests can
//! cover the path without spinning up an Actix test harness.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{Error as ActixError, HttpResponse};

/// Request header carrying the CSRF token. Clients (frontend fetch /
/// axios wrappers) set this on every state-changing request; its value
/// is whatever the client produced (we don't validate content).
pub const CSRF_HEADER: &str = "X-CSRF-Token";

/// Header used by non-browser clients for API-key authentication. Such
/// clients are exempt from the CSRF requirement.
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
        let has_csrf_token = req.headers().contains_key(CSRF_HEADER);

        Box::pin(async move {
            if should_require_csrf_token(&path, &method, has_api_key) && !has_csrf_token {
                let resp = HttpResponse::Forbidden().json(serde_json::json!({
                    "error": "Missing CSRF token",
                    "header": CSRF_HEADER,
                }));
                return Ok(req.into_response(resp).map_into_right_body());
            }
            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}

/// Decide whether a request must present a CSRF token. The rules are
/// extracted as a free function so the middleware is a thin shim and
/// the policy can be unit-tested without an HTTP harness.
pub fn should_require_csrf_token(path: &str, method: &Method, has_api_key: bool) -> bool {
    if has_api_key {
        return false;
    }
    if !is_state_changing(method) {
        return false;
    }
    if is_csrf_exempt_path(path) {
        return false;
    }
    true
}

fn is_state_changing(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Paths that cannot meaningfully carry a CSRF token because the
/// session that would mint one hasn't been established yet, or because
/// the route uses a protocol outside the CSRF threat model.
fn is_csrf_exempt_path(path: &str) -> bool {
    // Login / setup bootstrap: no session yet, so no token to match.
    if path == "/api/auth/login" || path.starts_with("/api/setup/") {
        return true;
    }
    // WebSocket upgrade happens over a GET anyway, but list the prefix
    // explicitly so the intent is visible when someone reads the file.
    if path.starts_with("/ws/") {
        return true;
    }
    false
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
        // Login hasn't yet issued a session, so there's no token to carry.
        assert!(!should_require_csrf_token("/api/auth/login", &Method::POST, false));
        assert!(!should_require_csrf_token(
            "/api/setup/initialize",
            &Method::POST,
            false
        ));
    }

    #[test]
    fn websocket_upgrade_is_exempt() {
        // WS upgrade is a GET anyway but stays exempt under any verb.
        assert!(!should_require_csrf_token("/ws/events", &Method::GET, false));
        assert!(!should_require_csrf_token("/ws/events", &Method::POST, false));
    }

    #[test]
    fn api_key_clients_are_exempt_even_on_state_changing_routes() {
        // Non-browser clients present a sealed credential; CSRF is a
        // browser threat model.
        assert!(!should_require_csrf_token("/api/acl/rules", &Method::POST, true));
        assert!(!should_require_csrf_token("/api/soar/playbooks", &Method::DELETE, true));
    }

    #[test]
    fn api_key_exemption_takes_precedence_over_path_rules() {
        // Even if the path is a state-changing admin route, the API-key
        // header flips the requirement off before the path check runs.
        assert!(!should_require_csrf_token("/api/system/reload", &Method::POST, true));
    }
}
