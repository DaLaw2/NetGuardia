use actix_web::{web, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/ml")
        .route("/status", web::get().to(get_status))
}

async fn get_status() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "active": true
    }))
}
