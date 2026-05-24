use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{Error as ActixError, HttpResponse, web};

use crate::adapter::http::helpers::json_error;
use crate::infrastructure::http_runtime::SetupCompleteFlag;

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
            service: Rc::new(service),
        }))
    }
}

pub struct SetupGuardService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for SetupGuardService<S>
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
            let setup_complete = req
                .app_data::<web::Data<SetupCompleteFlag>>()
                .map(|flag| flag.is_complete())
                .unwrap_or(false);

            if setup_complete {
                if path.starts_with("/api/setup/") && path != "/api/setup/status" {
                    let resp = json_error(StatusCode::GONE, "Setup already completed");
                    return Ok(req.into_response(resp).map_into_right_body());
                }
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }
            if path.starts_with("/api/setup/")
                || path.starts_with("/api/health/")
                || path == "/api/auth/login"
                || !path.starts_with("/api/")
            {
                let res = service.call(req).await?.map_into_left_body();
                return Ok(res);
            }
            let resp = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "System setup in progress",
                "setup_required": true,
                "message": "Please complete the setup wizard at /setup"
            }));
            Ok(req.into_response(resp).map_into_right_body())
        })
    }
}
