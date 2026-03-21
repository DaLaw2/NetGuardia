use std::sync::Arc;

use actix_web::web::route;
use actix_web::{web, App, HttpServer};

use crate::core::auth::jwt::JwtService;
use crate::adapter::persistence::Database;
use crate::core::ebpf::EbpfServices;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::core::ml::config_loader::InferenceConfig;
#[cfg(feature = "license")]
use crate::core::license::LicenseInfo;
use crate::model::error::http::HttpError;
use crate::model::error::Error;
use crate::adapter::http::{acl, auth, default, filter, health as health_api, ml, rate_limit as rate_limit_api, stats, system as system_api};
use crate::adapter::websocket::routes as ws;
use crate::interface::port::repository::RepositoryPort;

/// Parameters for starting the HTTP server, avoiding `#[cfg]` on function params.
pub struct HttpServerParams {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    #[cfg(feature = "license")]
    pub license_info: Arc<LicenseInfo>,
}

/// Run the HTTP server with the given parameters.
pub async fn run(params: HttpServerParams) -> Result<(), Error> {
    let access_control = params.ebpf_services.access_control.clone();
    let protocol_filter = params.ebpf_services.protocol_filter.clone();
    let dns_filter = params.ebpf_services.dns_filter.clone();
    let geo_block = params.ebpf_services.geo_block.clone();
    let rate_limit = params.ebpf_services.rate_limit.clone();
    let health = params.app_services.health.clone();
    let ml_alert = params.app_services.ml_alert.clone();
    let ml_engine = params.app_services.ml_engine.clone();
    let flow_statistics = params.app_services.flow_statistics.clone();
    let drop_monitor = params.ebpf_services.drop_monitor.clone();
    let app_config = params.app_config;
    let inference_config = params.inference_config;
    let db = params.db;
    let jwt_service = params.jwt_service;
    let comm = params.comm;
    #[cfg(feature = "license")]
    let license_info = params.license_info;
    let port = app_config.http.http_server_bind_port;

    HttpServer::new(move || {
        let cors = actix_cors::Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);
        let app = App::new()
            .wrap(cors)
            .app_data(web::Data::from(app_config.clone()))
            .app_data(web::Data::from(inference_config.clone()))
            .app_data(web::Data::from(access_control.clone()))
            .app_data(web::Data::from(protocol_filter.clone()))
            .app_data(web::Data::from(dns_filter.clone()))
            .app_data(web::Data::from(geo_block.clone()))
            .app_data(web::Data::from(rate_limit.clone()))
            .app_data(web::Data::from(health.clone()))
            .app_data(web::Data::from(ml_alert.clone()))
            .app_data(web::Data::from(ml_engine.clone()))
            .app_data(web::Data::from(flow_statistics.clone()))
            .app_data(web::Data::from(drop_monitor.clone()))
            .app_data(web::Data::from(db.clone() as Arc<dyn RepositoryPort>))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::from(comm.clone()));
        #[cfg(feature = "license")]
        let app = app.app_data(web::Data::from(license_info.clone()));
        app.service(
                web::scope("/api")
                    .wrap(crate::core::auth::middleware::AuthMiddleware)
                    .service(auth::initialize())
                    .service(acl::initialize())
                    .service(filter::initialize())
                    .service(rate_limit_api::initialize())
                    .service(stats::initialize())
                    .service(health_api::initialize())
                    .service(ml::initialize())
                    .service(system_api::initialize())
            )
            .service(ws::initialize())
            .default_service(route().to(default::default_route))
    })
    .bind(format!("0.0.0.0:{}", port))
    .map_err(HttpError::BindPortError)?
    .run()
    .await
    .map_err(HttpError::ServerPanic)?;
    Ok(())
}
