use actix_web::{web, Scope};

pub fn initialize() -> Scope {
    web::scope("/sampling")
}
