use actix_web::{web, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    let scope = web::scope("/system")
        .route("/boot-time", web::get().to(get_boot_time));

    #[cfg(feature = "license")]
    let scope = scope.route("/license", web::get().to(get_license_info));

    scope
}

async fn get_boot_time() -> impl Responder {
    HttpResponse::Ok().json(crate::utils::boot_time::boot_time())
}

#[cfg(feature = "license")]
async fn get_license_info(license_info: web::Data<crate::core::license::LicenseInfo>) -> impl Responder {
    HttpResponse::Ok().json(license_info.get_ref())
}
