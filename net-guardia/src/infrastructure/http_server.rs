use std::sync::Arc;

use actix_web::web::route;
use actix_web::{web, App, HttpServer};

use crate::core::acl_service::AclService;
use crate::core::auth::jwt::JwtService;
use crate::core::config_service::ConfigService;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::adapter::persistence::Database;
use crate::core::ebpf::EbpfServices;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::core::ml::config_loader::InferenceConfig;
use macros::log;
use crate::model::error::http::HttpError;
use crate::model::error::Error;
use crate::model::log::http::HttpLog;
use crate::adapter::http::{acl, auth, default, filter, health as health_api, mcp_keys, ml, notification as notification_api, rate_limit as rate_limit_api, report as report_api, setup as setup_api, soar, stats, system as system_api};
use crate::core::auth::setup_guard::{SetupCompleteFlag, SetupGuard};
use crate::adapter::websocket::routes as ws;
use crate::interface::port::repository::RepositoryPort;

/// Shared flag: true when all services (eBPF, ML, SOAR) are fully initialized.
pub type ReadyFlag = Arc<std::sync::atomic::AtomicBool>;

/// Parameters for starting the HTTP server, avoiding `#[cfg]` on function params.
pub struct HttpServerParams {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    pub setup_complete: SetupCompleteFlag,
    pub ready: ReadyFlag,
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
}

/// CORS configuration shared by both full and setup servers.
///
/// When `allowed_origins` is non-empty, only those exact origins are permitted.
/// When empty, RFC 1918 private-network origins (localhost, 127.0.0.1,
/// 192.168.x.x, 10.x.x.x, 172.16-31.x.x) are allowed.
fn cors(allowed_origins: Vec<String>) -> actix_cors::Cors {
    actix_cors::Cors::default()
        .allowed_origin_fn(move |origin, _req_head| {
            let origin_str = origin.to_str().unwrap_or("");
            if !allowed_origins.is_empty() {
                return allowed_origins.iter().any(|o| o == origin_str);
            }
            // Default: RFC 1918 private networks only
            let bytes = origin.as_bytes();
            bytes.starts_with(b"http://localhost:")
                || bytes.starts_with(b"http://127.0.0.1:")
                || bytes.starts_with(b"https://localhost:")
                || bytes.starts_with(b"https://127.0.0.1:")
                || bytes.starts_with(b"http://192.168.")
                || bytes.starts_with(b"https://192.168.")
                || bytes.starts_with(b"http://10.")
                || bytes.starts_with(b"https://10.")
                || is_rfc1918_172(bytes)
        })
        .allow_any_method()
        .allow_any_header()
        .max_age(3600)
}

/// Check if origin is from RFC 1918 172.16-31.x.x range.
fn is_rfc1918_172(origin: &[u8]) -> bool {
    for prefix in [b"http://172." as &[u8], b"https://172." as &[u8]] {
        if origin.starts_with(prefix) {
            let rest = &origin[prefix.len()..];
            if let Some(dot_pos) = rest.iter().position(|&b| b == b'.')
                && let Some(second_octet) = std::str::from_utf8(&rest[..dot_pos])
                    .ok()
                    .and_then(|s| s.parse::<u8>().ok())
            {
                return (16..=31).contains(&second_octet);
            }
        }
    }
    false
}

/// Default fallback port when the configured port is unavailable.
const FALLBACK_PORT: u16 = 8080;

/// Minimal HTTP server for setup wizard mode.
/// Only serves setup, auth, and health routes — no eBPF/ML dependencies.
/// Returns a ServerHandle so the caller can stop it after setup completes.
pub fn start_setup_server(
    db: Arc<Database>,
    jwt_service: Arc<JwtService>,
    setup_complete: SetupCompleteFlag,
    port: u16,
) -> Result<actix_web::dev::ServerHandle, Error> {
    let make_app = move || {
        App::new()
            .wrap(cors(vec![]))
            .app_data(web::Data::from(db.clone() as Arc<dyn RepositoryPort>))
            .app_data(web::Data::from(db.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .service(
                web::scope("/api")
                    .wrap(crate::core::auth::middleware::AuthMiddleware)
                    .service(auth::initialize())
                    .service(setup_api::initialize())
                    .service(health_api::initialize())
            )
            .default_service(route().to(default::default_route))
    };

    let server = match HttpServer::new(make_app.clone())
        .workers(1)
        .shutdown_timeout(1) // Fast shutdown — no long-lived connections to drain
        .bind(format!("0.0.0.0:{}", port))
    {
        Ok(s) => s,
        Err(e) if port != FALLBACK_PORT => {
            log!(HttpLog::SetupBindFallback(port, e.to_string(), FALLBACK_PORT));
            HttpServer::new(make_app)
                .workers(1)
                .shutdown_timeout(1)
                .bind(format!("0.0.0.0:{}", FALLBACK_PORT))
                .map_err(HttpError::BindPortError)?
        }
        Err(e) => return Err(HttpError::BindPortError(e).into()),
    }
    .run();

    let handle = server.handle();

    // Spawn the server in background (!Send future, use actix::spawn)
    actix::spawn(async move {
        if let Err(e) = server.await {
            log!(HttpLog::SetupServerError(e.to_string()));
        }
    });

    Ok(handle)
}

/// Run the full HTTP server with all services.
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
    let setup_complete = params.setup_complete;
    let ready = params.ready;
    let acl_service = params.acl_service;
    let config_service = params.config_service;
    let dns_filter_service = params.dns_filter_service;
    let notification_service = params.notification_service;
    let playbook_service = params.playbook_service;
    let rate_limit_service = params.rate_limit_service;
    let port = app_config.http.http_server_bind_port;

    HttpServer::new(move || {
        let app = App::new()
            .wrap(cors(app_config.http.cors_allowed_origins.clone()))
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
            .app_data(web::Data::from(db.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::from(comm.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .app_data(web::Data::new(ready.clone()))
            .app_data(web::Data::from(acl_service.clone()))
            .app_data(web::Data::from(config_service.clone()))
            .app_data(web::Data::from(dns_filter_service.clone()))
            .app_data(web::Data::from(notification_service.clone()))
            .app_data(web::Data::from(playbook_service.clone()))
            .app_data(web::Data::from(rate_limit_service.clone()));
        app.wrap(SetupGuard)
            .service(
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
                    .service(soar::initialize())
                    .service(notification_api::initialize())
                    .service(report_api::initialize())
                    .service(mcp_keys::initialize())
                    .service(setup_api::initialize())
            )
            .service(ws::initialize())
            // Health-ready endpoint outside /api scope — no auth, no SetupGuard.
            // Path intentionally NOT under /api/ to avoid AuthMiddleware.
            .route("/health/ready", web::get().to(health_ready))
            .default_service(route().to(default::default_route))
    })
    .bind(format!("0.0.0.0:{}", port))
    .map_err(HttpError::BindPortError)?
    .run()
    .await
    .map_err(HttpError::ServerPanic)?;
    Ok(())
}

async fn health_ready(ready: web::Data<ReadyFlag>) -> actix_web::HttpResponse {
    let is_ready = ready.load(std::sync::atomic::Ordering::SeqCst);
    actix_web::HttpResponse::Ok().json(serde_json::json!({"ready": is_ready}))
}
