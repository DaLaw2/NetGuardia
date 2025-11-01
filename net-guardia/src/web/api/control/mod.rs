pub mod access_control;
pub mod service;
pub mod statistics;
pub mod health;

use actix_web::{web, Scope};

pub fn initialize() -> Scope {
    web::scope("/ebpf")
        .service(access_control::initialize())
        .service(service::initialize())
        .service(statistics::initialize())
        .service(health::initialize())
}
