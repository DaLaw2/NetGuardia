pub mod access_control;
pub mod protocol_filter;
pub mod statistics;

use actix_web::{web, Scope};

pub fn initialize() -> Scope {
    web::scope("/ebpf")
        .service(access_control::initialize())
        .service(protocol_filter::initialize())
        .service(
            web::scope("/statistics")
                .route("/flows", web::get().to(statistics::get_all_flows))
                .route("/flows/top/{n}", web::get().to(statistics::get_top_flows))
                .route("/summary", web::get().to(statistics::get_summary)),
        )
}
