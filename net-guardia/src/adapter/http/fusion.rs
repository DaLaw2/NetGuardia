//! HTTP surface for fusion-layer observability. Reads shared atomic
//! counters maintained by the detection orchestrator — handlers here
//! never touch orchestrator state, so a hung dashboard cannot stall
//! the detection pipeline.

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, Scope, web};

use crate::core::detection::metrics::FusionMetrics;

pub fn initialize() -> Scope {
    web::scope("/fusion").route("/metrics", web::get().to(get_metrics))
}

/// `GET /api/fusion/metrics` — lock-free snapshot of fusion counters and
/// derived rates. Drives the operator dashboard's "how well is fusion
/// working on my network?" view.
async fn get_metrics(metrics: web::Data<Arc<FusionMetrics>>) -> impl Responder {
    HttpResponse::Ok().json(metrics.snapshot())
}
