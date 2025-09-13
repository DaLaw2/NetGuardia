use actix_web::{web, Scope};

pub mod access_control;
pub mod service;

pub fn initialize() -> Scope {
    web::scope("/control")
        .service(access_control::initialize())
        .service(service::initialize())
}
