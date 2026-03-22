use actix_web::{web, HttpResponse, Responder, Scope};

use crate::core::ebpf::drop_monitor::DropMonitor;
use crate::infrastructure::statistics::FlowStatistics;

pub fn initialize() -> Scope {
    web::scope("/stats")
        .route("/flows", web::get().to(get_all_flows))
        .route("/flows/top/{n}", web::get().to(get_top_flows))
        .route("/summary", web::get().to(get_summary))
        .route("/drops", web::get().to(get_drop_stats))
}

async fn get_all_flows(stats: web::Data<FlowStatistics>) -> impl Responder {
    HttpResponse::Ok().json(stats.get_all_flows())
}

async fn get_top_flows(
    stats: web::Data<FlowStatistics>,
    path: web::Path<usize>,
) -> impl Responder {
    let n = path.into_inner();
    HttpResponse::Ok().json(stats.get_top_flows(n))
}

async fn get_summary(stats: web::Data<FlowStatistics>) -> impl Responder {
    HttpResponse::Ok().json(stats.get_summary())
}

async fn get_drop_stats(monitor: web::Data<DropMonitor>) -> impl Responder {
    HttpResponse::Ok().json(monitor.get_counters())
}
