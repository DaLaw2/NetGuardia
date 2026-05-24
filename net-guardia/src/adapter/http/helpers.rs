use std::fmt;

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use serde::Serialize;

pub fn ok_or_error<T, E: fmt::Display>(result: Result<T, E>) -> HttpResponse {
    match result {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => internal_error(e),
    }
}

pub fn ok_json_or_error<T: Serialize, E: fmt::Display>(result: Result<T, E>) -> HttpResponse {
    match result {
        Ok(value) => HttpResponse::Ok().json(value),
        Err(e) => internal_error(e),
    }
}

pub fn internal_error<E: fmt::Display>(error: E) -> HttpResponse {
    json_error(StatusCode::INTERNAL_SERVER_ERROR, error)
}

pub fn bad_request<E: fmt::Display>(error: E) -> HttpResponse {
    json_error(StatusCode::BAD_REQUEST, error)
}

pub fn not_found<E: fmt::Display>(error: E) -> HttpResponse {
    json_error(StatusCode::NOT_FOUND, error)
}

pub fn forbidden<E: fmt::Display>(error: E) -> HttpResponse {
    json_error(StatusCode::FORBIDDEN, error)
}

pub fn conflict<E: fmt::Display>(error: E) -> HttpResponse {
    json_error(StatusCode::CONFLICT, error)
}

pub fn json_error<E: fmt::Display>(status: StatusCode, error: E) -> HttpResponse {
    HttpResponse::build(status).json(serde_json::json!({"error": error.to_string()}))
}
