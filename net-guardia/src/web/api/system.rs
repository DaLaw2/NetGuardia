use actix_web::{web, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/system")
        .route("/boot-time", web::get().to(get_boot_time))
}

async fn get_boot_time() -> impl Responder {
    HttpResponse::Ok().json(crate::utils::boot_time::boot_time())
}
