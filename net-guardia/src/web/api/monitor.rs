use crate::utils::static_file::StaticFiles;
use actix_web::{get, post, web, HttpResponse, Responder, Scope};

pub fn initialize() -> Scope {
    web::scope("/monitor")
}
