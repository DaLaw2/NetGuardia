use actix_web::{web, HttpResponse, Responder};

use crate::core::infrastructure::statistics::FlowStatistics;

pub async fn get_all_flows(stats: web::Data<FlowStatistics>) -> impl Responder {
    HttpResponse::Ok().json(stats.get_all_flows())
}

pub async fn get_top_flows(
    stats: web::Data<FlowStatistics>,
    path: web::Path<usize>,
) -> impl Responder {
    let n = path.into_inner();
    HttpResponse::Ok().json(stats.get_top_flows(n))
}

pub async fn get_summary(stats: web::Data<FlowStatistics>) -> impl Responder {
    HttpResponse::Ok().json(stats.get_summary())
}
