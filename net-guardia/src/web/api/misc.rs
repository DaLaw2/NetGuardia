use actix_web::{get, web, HttpResponse, Responder, Scope};

use crate::utils::boot_time::boot_time;

pub fn initialize() -> Scope {
    web::scope("/misc")
        .service(get_boot_time)
}

#[get("/boot_time")]
async fn get_boot_time() -> impl Responder {
    let boot_time = boot_time();
    HttpResponse::Ok().json(boot_time)
}
