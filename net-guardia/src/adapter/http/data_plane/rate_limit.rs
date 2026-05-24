use actix_web::{HttpResponse, Responder, Scope, web};

use crate::adapter::http::helpers::{bad_request, internal_error, ok_json_or_error};
use crate::common::error::Error;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::domain::common::system::rate_limit_settings::RateLimitSettings;
use crate::domain::data_plane::error::EbpfError;

pub fn initialize() -> Scope {
    web::scope("/rate-limit")
        .route("/config", web::get().to(get_config))
        .route("/config", web::put().to(set_config))
}

async fn get_config(service: web::Data<RateLimitService>) -> impl Responder {
    ok_json_or_error(service.current_settings())
}

async fn set_config(settings: web::Json<RateLimitSettings>, service: web::Data<RateLimitService>) -> impl Responder {
    match service.update(&settings.into_inner()).await {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(error) => rate_limit_error(error),
    }
}

fn rate_limit_error(error: Error) -> HttpResponse {
    match &error {
        Error::Ebpf(EbpfError::InvalidRateLimitValue { .. }) => bad_request(error),
        _ => internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;

    use super::*;

    #[test]
    fn invalid_rate_limit_values_are_bad_requests() {
        let response = rate_limit_error(EbpfError::InvalidRateLimitValue("packet_rate".to_string(), 0_u64).into());

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
