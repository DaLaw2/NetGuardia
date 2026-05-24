use actix_web::web;

use crate::adapter::http::data_plane::{acl, filter, rate_limit};
use crate::adapter::http::detection::{byo, flow_trace, fusion, health, ml, model_upload, stats};
use crate::adapter::http::identity::{api_keys, auth};
use crate::adapter::http::middleware::auth::AuthMiddleware;
use crate::adapter::http::middleware::csrf::CsrfMiddleware;
use crate::adapter::http::response::{notification, report, soar};
use crate::adapter::http::{audit, logs, setup, system};

pub fn configure_setup_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .wrap(AuthMiddleware)
            .service(auth::initialize())
            .service(setup::initialize())
            .service(health::initialize()),
    );
}

pub fn configure_authenticated_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .wrap(CsrfMiddleware)
            .wrap(AuthMiddleware)
            .service(health::initialize())
            .service(ml::initialize())
            .service(model_upload::initialize())
            .service(byo::initialize())
            .service(fusion::initialize())
            .service(flow_trace::initialize())
            .service(stats::initialize())
            .service(auth::initialize())
            .service(acl::initialize())
            .service(filter::initialize())
            .service(rate_limit::initialize())
            .service(soar::initialize())
            .service(notification::initialize())
            .service(report::initialize())
            .service(system::initialize())
            .service(setup::initialize())
            .service(api_keys::initialize())
            .service(logs::initialize())
            .service(audit::initialize()),
    );
}
