use std::fmt;

use actix_web::HttpResponse;
use serde::Serialize;

pub fn ok_or_error<T, E: fmt::Display>(result: Result<T, E>) -> HttpResponse {
    match result {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

pub fn ok_json_or_error<T: Serialize, E: fmt::Display>(result: Result<T, E>) -> HttpResponse {
    match result {
        Ok(value) => HttpResponse::Ok().json(value),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}
