use std::sync::atomic::Ordering::SeqCst;

use actix_web::{HttpResponse, web};

use crate::infrastructure::http_runtime::ReadyFlag;
use crate::interface::system::http_runtime::ReadinessQuery;

pub async fn health_ready(ready: web::Data<ReadyFlag>, state: web::Data<dyn ReadinessQuery>) -> HttpResponse {
    HttpResponse::Ok().json(state.snapshot(ready.0.load(SeqCst)))
}
