use actix_web::{get, web, HttpResponse, Responder, Scope};
use crate::core::system::System;

pub fn initialize() -> Scope {
    web::scope("/misc")
        .service(boot_time)
}

#[get("/boot_time")]
async fn boot_time() -> impl Responder {
    let boot_time = System::boot_time().await;
    HttpResponse::Ok().json(boot_time)
}
