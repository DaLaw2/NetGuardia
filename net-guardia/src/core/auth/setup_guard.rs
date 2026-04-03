use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error as ActixError, HttpResponse, web};

/// Shared flag indicating whether setup has completed.
/// When false, only setup wizard routes are allowed; all others get 503.
pub type SetupCompleteFlag = Arc<AtomicBool>;

pub struct SetupGuard;

impl<S, B> Transform<S, ServiceRequest> for SetupGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Transform = SetupGuardService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SetupGuardService {
            service: std::rc::Rc::new(service),
        }))
    }
}

pub struct SetupGuardService<S> {
    service: std::rc::Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SetupGuardService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut core::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = std::rc::Rc::clone(&self.service);

        Box::pin(async move {
            let path = req.path().to_string();

            // Check setup_complete flag from app data
            let setup_complete = req
                .app_data::<web::Data<SetupCompleteFlag>>()
                .map(|flag| flag.load(Ordering::SeqCst))
                .unwrap_or(true); // Default to true if flag not found

            if setup_complete {
                // Normal mode: pass through, but block setup mutation endpoints.
                // Allow /api/setup/status (read-only) so frontend can check setup state.
                if path.starts_with("/api/setup/") && path != "/api/setup/status" {
                    let resp = HttpResponse::Gone().json(serde_json::json!({"error": "Setup already completed"}));
                    return Ok(req.into_response(resp).map_into_right_body());
                }
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Setup mode: only allow setup wizard and health endpoints
            if path.starts_with("/api/setup/")
                || path.starts_with("/api/health/")
                || path == "/api/auth/login"
                || !path.starts_with("/api/")
            {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }

            // Block all other API routes with 503
            let resp = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "System setup in progress",
                "setup_required": true,
                "message": "Please complete the setup wizard at /setup"
            }));
            Ok(req.into_response(resp).map_into_right_body())
        })
    }
}
