use actix_web::{web, Scope};

pub mod access_list;
pub mod defence;
pub mod sampling;
pub mod service;

pub fn initialize() -> Scope {
    web::scope("/control")
        .service(access_list::initialize())
        .service(defence::initialize())
        .service(sampling::initialize())
        .service(service::initialize())
}
