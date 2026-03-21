use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{web, Error as ActixError, HttpMessage, HttpResponse};

use crate::core::auth::jwt::JwtService;

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

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            let path = req.path().to_string();

            // Skip auth for login endpoint and non-API routes
            if path == "/api/auth/login" || !path.starts_with("/api/") {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Extract JWT service from app data
            let jwt_service = match req.app_data::<web::Data<JwtService>>() {
                Some(s) => s.clone(),
                None => {
                    let resp = HttpResponse::InternalServerError()
                        .json(serde_json::json!({"error": "Auth not configured"}));
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            // Extract token from Authorization header
            let auth_header = req.headers().get("Authorization");
            let token = match auth_header {
                Some(val) => {
                    let val_str = val.to_str().unwrap_or("");
                    if val_str.starts_with("Bearer ") {
                        &val_str[7..]
                    } else {
                        let resp = HttpResponse::Unauthorized()
                            .json(serde_json::json!({"error": "Invalid authorization header"}));
                        return Ok(req.into_response(resp).map_into_right_body());
                    }
                }
                None => {
                    let resp = HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Missing authorization header"}));
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            // Validate token
            let claims = match jwt_service.validate_token(token) {
                Ok(c) => c,
                Err(_) => {
                    let resp = HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Invalid or expired token"}));
                    return Ok(req.into_response(resp).map_into_right_body());
                }
            };

            // RBAC: viewer can only GET
            if claims.role == "viewer" && req.method() != actix_web::http::Method::GET {
                let resp = HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "Insufficient permissions"}));
                return Ok(req.into_response(resp).map_into_right_body());
            }

            // Store claims in request extensions
            req.extensions_mut().insert(claims);

            let res = service.call(req).await?.map_into_left_body();
            Ok(res)
        })
    }
}
