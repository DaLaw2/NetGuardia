use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use actix_cors::Cors;
use actix_web::dev::ServerHandle;
use actix_web::web::route;
use actix_web::{App, HttpServer, web};
use arc_swap::ArcSwap;
use macros::log;
use tokio::sync::broadcast;

use crate::adapter::ebpf::EbpfServices;
use crate::adapter::http::data_plane::{acl, filter, rate_limit as rate_limit_api};
use crate::adapter::http::default;
use crate::adapter::http::detection::model_upload::PromoteGate;
use crate::adapter::http::detection::{byo, flow_trace, fusion, health as health_api, ml, model_upload, stats};
use crate::adapter::http::identity::{api_keys, auth};
use crate::adapter::http::jwt::JwtService;
use crate::adapter::http::middleware::auth::AuthMiddleware;
use crate::adapter::http::middleware::csrf::CsrfMiddleware;
use crate::adapter::http::middleware::https_redirect::HttpsRedirect;
use crate::adapter::http::middleware::setup_guard::SetupGuard;
use crate::adapter::http::ready;
use crate::adapter::http::response::{notification as notification_api, report as report_api, soar};
use crate::adapter::http::{audit as audit_api, logs as logs_api, setup as setup_api, system as system_api};
use crate::adapter::persistence::Database;
use crate::adapter::websocket::routes as ws;
use crate::core::common::config_service::ConfigService;
use crate::core::common::enforce_mode_handler::EnforceModeHandler;
use crate::core::common::notification_service::NotificationService;
use crate::core::common::statistics::FlowStatistics;
use crate::core::data_plane::acl_service::AclService;
use crate::core::data_plane::dns_filter_service::DnsFilterService;
use crate::core::data_plane::rate_limit_service::RateLimitService;
use crate::core::identity::auth_service::AuthService;
use crate::core::response::engine::SoarEngine;
use crate::core::response::playbook_service::PlaybookService;
use crate::domain::common::config::AppConfig;
use crate::domain::common::config::constants::HTTP_FALLBACK_PORT;
use crate::domain::common::error::Error;
use crate::domain::common::error::http::HttpError;
use crate::domain::common::event::{AuditEvent, ThreatDetectedEvent};
use crate::domain::common::log::http::HttpLog;
use crate::domain::detection::ml_inference_config::MLInferenceConfig;
use crate::infrastructure::health::SystemHealth;
use crate::infrastructure::inference_runtime::InferenceRuntime;
use crate::infrastructure::log_buffer::LogBuffer;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::readiness::ReadinessState;
use crate::infrastructure::runtime_state::RuntimeState;
use crate::infrastructure::secret_store::SecretStore;
use crate::infrastructure::suricata_manager::SuricataManager;
use crate::infrastructure::system::ShutdownHandle;
use crate::interface::api_key::ApiKeyRepo;
use crate::interface::app_repo::AppRepo;
use crate::interface::audit::AuditRepo;
use crate::interface::drop_stats::DropStatsPort;
use crate::interface::protocol_filter::ProtocolFilterPort;

#[derive(Clone)]
pub struct SetupCompleteFlag(pub Arc<AtomicBool>);

#[derive(Clone)]
pub struct ReadyFlag(pub Arc<AtomicBool>);

#[derive(Clone)]
pub struct ForceHttpsFlag(pub Arc<AtomicBool>);

pub struct HttpServerParams {
    pub app_config: Arc<ArcSwap<AppConfig>>,
    pub runtime_state: Arc<ArcSwap<RuntimeState>>,
    pub inference_config: Arc<MLInferenceConfig>,

    pub database: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub logger: Arc<Logger>,
    pub log_buffer: Arc<LogBuffer>,

    pub ebpf_services: Arc<EbpfServices>,
    pub inference_runtime: Arc<InferenceRuntime>,
    pub health: Arc<SystemHealth>,
    pub flow_statistics: Arc<FlowStatistics>,

    pub jwt_service: Arc<JwtService>,
    pub auth_service: Arc<AuthService>,
    pub enforce_handler: Arc<EnforceModeHandler>,

    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub soar_engine: Arc<SoarEngine>,
    pub suricata_manager: Arc<SuricataManager>,

    pub threat_tx: broadcast::Sender<ThreatDetectedEvent>,
    pub audit_tx: broadcast::Sender<AuditEvent>,

    pub setup_complete: SetupCompleteFlag,
    pub ready: ReadyFlag,
    pub readiness_state: Arc<ReadinessState>,
    pub force_https: ForceHttpsFlag,
    pub shutdown_handle: Arc<ShutdownHandle>,
}

fn cors(allowed_origins: Vec<String>) -> Cors {
    Cors::default()
        .allowed_origin_fn(move |origin, _req_head| {
            let origin_str = origin.to_str().unwrap_or("");
            if !allowed_origins.is_empty() {
                return allowed_origins.iter().any(|o| o == origin_str);
            }
            is_private_origin(origin_str)
        })
        .allow_any_method()
        .allow_any_header()
        .max_age(3600)
}

fn extract_origin_host(origin: &str) -> Option<&str> {
    let after_scheme = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    if after_scheme.starts_with('[') {
        let bracket_end = after_scheme.find(']')?;
        Some(&after_scheme[1..bracket_end])
    } else {
        Some(after_scheme.split(':').next().unwrap_or(after_scheme))
    }
}

fn is_private_origin(origin: &str) -> bool {
    let host = match extract_origin_host(origin) {
        Some(h) => h,
        None => return false,
    };

    if host == "localhost" {
        return true;
    }

    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        return octets[0] == 127                                         // 127.0.0.0/8
            || octets[0] == 10                                          // 10.0.0.0/8
            || (octets[0] == 172 && (16..=31).contains(&octets[1])) // 172.16.0.0/12
            || (octets[0] == 192 && octets[1] == 168); // 192.168.0.0/16
    }

    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        return ipv6.is_loopback();
    }

    false
}

pub struct SetupServerParams {
    pub database: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub jwt_service: Arc<JwtService>,
    pub auth_service: Arc<AuthService>,
    pub setup_complete: SetupCompleteFlag,
    pub port: u16,
}

pub fn start_setup_server(params: SetupServerParams) -> Result<ServerHandle, Error> {
    let database = params.database;
    let secret_store = params.secret_store;
    let jwt_service = params.jwt_service;
    let auth_service = params.auth_service;
    let setup_complete = params.setup_complete;
    let port = params.port;

    let app = move || {
        App::new()
            .wrap(cors(vec![]))
            .app_data(web::Data::from(database.clone() as Arc<dyn AppRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn ApiKeyRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn AuditRepo>))
            .app_data(web::Data::from(database.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::from(auth_service.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .service(
                web::scope("/api")
                    .wrap(AuthMiddleware)
                    .service(auth::initialize())
                    .service(setup_api::initialize())
                    .service(health_api::initialize()),
            )
            .default_service(route().to(default::default_route))
    };

    let server = match HttpServer::new(app.clone())
        .workers(1)
        .shutdown_timeout(1)
        .bind(format!("0.0.0.0:{}", port))
    {
        Ok(s) => s,
        Err(err) if port != HTTP_FALLBACK_PORT => {
            log!(HttpLog::SetupBindFallback(port, err.to_string(), HTTP_FALLBACK_PORT));
            HttpServer::new(app)
                .workers(1)
                .shutdown_timeout(1)
                .bind(format!("0.0.0.0:{}", HTTP_FALLBACK_PORT))
                .map_err(HttpError::BindPortError)?
        }
        Err(err) => Err(HttpError::BindPortError(err))?,
    }
    .run();

    let handle = server.handle();

    actix::spawn(async move {
        if let Err(e) = server.await {
            log!(HttpLog::SetupServerError(e.to_string()));
        }
    });

    Ok(handle)
}

pub async fn run(params: HttpServerParams) -> Result<(), Error> {
    let app_config = params.app_config;
    let runtime_state = params.runtime_state;
    let inference_config = params.inference_config;

    let database = params.database;
    let secret_store = params.secret_store;
    let logger = params.logger;
    let log_buffer = params.log_buffer;

    let access_control = params.ebpf_services.access_control.clone();
    let protocol_filter: Arc<dyn ProtocolFilterPort> = params.ebpf_services.protocol_filter.clone();
    let geo_block = params.ebpf_services.geo_block.clone();
    let rate_limit = params.ebpf_services.rate_limit.clone();
    let drop_monitor = params.ebpf_services.drop_monitor.clone();
    let drop_stats: Arc<dyn DropStatsPort> = drop_monitor.clone();
    let ml_alert = params.inference_runtime.ml_alert.clone();
    let ml_engine = params.inference_runtime.ml_engine.clone();
    let ml_inference = params.inference_runtime.ml_inference.clone();
    let fusion_metrics = params.inference_runtime.fusion_metrics.clone();
    let health = params.health;
    let flow_statistics = params.flow_statistics;

    let jwt_service = params.jwt_service;
    let auth_service = params.auth_service;
    let enforce_handler = params.enforce_handler;

    let acl_service = params.acl_service;
    let config_service = params.config_service;
    let dns_filter_service = params.dns_filter_service;
    let notification_service = params.notification_service;
    let playbook_service = params.playbook_service;
    let rate_limit_service = params.rate_limit_service;
    let soar_engine = params.soar_engine;
    let suricata_manager = params.suricata_manager;

    let threat_tx = params.threat_tx;
    let audit_tx = params.audit_tx;

    let setup_complete = params.setup_complete;
    let ready = params.ready;
    let readiness_state = params.readiness_state;
    let force_https = params.force_https;
    let shutdown_handle = params.shutdown_handle;

    let port = app_config.load().http_server.port;

    let promote_lock: Arc<PromoteGate> = Arc::new(PromoteGate::new());

    HttpServer::new(move || {
        let app = App::new()
            .wrap(HttpsRedirect)
            .wrap(cors(app_config.load().http_server.cors_allowed_origins.clone()))
            .app_data(web::Data::from(app_config.clone()))
            .app_data(web::Data::from(runtime_state.clone()))
            .app_data(web::Data::from(inference_config.clone()))
            .app_data(web::Data::from(database.clone() as Arc<dyn AppRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn ApiKeyRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn AuditRepo>))
            .app_data(web::Data::from(database.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(logger.clone()))
            .app_data(web::Data::from(log_buffer.clone()))
            .app_data(web::Data::from(access_control.clone()))
            .app_data(web::Data::from(protocol_filter.clone()))
            .app_data(web::Data::from(geo_block.clone()))
            .app_data(web::Data::from(rate_limit.clone()))
            .app_data(web::Data::from(drop_monitor.clone()))
            .app_data(web::Data::from(drop_stats.clone()))
            .app_data(web::Data::from(ml_alert.clone()))
            .app_data(web::Data::from(ml_engine.clone()))
            .app_data(web::Data::from(ml_inference.clone()))
            .app_data(web::Data::from(fusion_metrics.clone()))
            .app_data(web::Data::from(health.clone()))
            .app_data(web::Data::from(flow_statistics.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::from(auth_service.clone()))
            .app_data(web::Data::from(enforce_handler.clone()))
            .app_data(web::Data::from(acl_service.clone()))
            .app_data(web::Data::from(config_service.clone()))
            .app_data(web::Data::from(dns_filter_service.clone()))
            .app_data(web::Data::from(notification_service.clone()))
            .app_data(web::Data::from(playbook_service.clone()))
            .app_data(web::Data::from(rate_limit_service.clone()))
            .app_data(web::Data::from(soar_engine.clone()))
            .app_data(web::Data::from(suricata_manager.clone()))
            .app_data(web::Data::new(threat_tx.clone()))
            .app_data(web::Data::new(audit_tx.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .app_data(web::Data::new(ready.clone()))
            .app_data(web::Data::from(readiness_state.clone()))
            .app_data(web::Data::new(force_https.clone()))
            .app_data(web::Data::from(shutdown_handle.clone()))
            .app_data(web::Data::from(promote_lock.clone()));
        app.wrap(SetupGuard)
            .service(
                web::scope("/api")
                    .wrap(CsrfMiddleware)
                    .wrap(AuthMiddleware)
                    .service(health_api::initialize())
                    .service(ml::initialize())
                    .service(model_upload::initialize())
                    .service(byo::initialize())
                    .service(fusion::initialize())
                    .service(flow_trace::initialize())
                    .service(stats::initialize())
                    .service(auth::initialize())
                    .service(acl::initialize())
                    .service(filter::initialize())
                    .service(rate_limit_api::initialize())
                    .service(soar::initialize())
                    .service(notification_api::initialize())
                    .service(report_api::initialize())
                    .service(system_api::initialize())
                    .service(setup_api::initialize())
                    .service(api_keys::initialize())
                    .service(logs_api::initialize())
                    .service(audit_api::initialize()),
            )
            .service(ws::initialize())
            .route("/health/ready", web::get().to(ready::health_ready))
            .default_service(route().to(default::default_route))
    })
    .bind(format!("0.0.0.0:{}", port))
    .map_err(HttpError::BindPortError)?
    .run()
    .await
    .map_err(HttpError::ServerPanic)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_origin_host_ipv4() {
        assert_eq!(extract_origin_host("http://10.0.0.1:8080"), Some("10.0.0.1"));
        assert_eq!(extract_origin_host("https://192.168.1.1:443"), Some("192.168.1.1"));
        assert_eq!(extract_origin_host("http://127.0.0.1:3000"), Some("127.0.0.1"));
    }

    #[test]
    fn test_extract_origin_host_hostname() {
        assert_eq!(extract_origin_host("http://localhost:8080"), Some("localhost"));
        assert_eq!(
            extract_origin_host("http://10.malware.net:8080"),
            Some("10.malware.net")
        );
    }

    #[test]
    fn test_extract_origin_host_ipv6() {
        assert_eq!(extract_origin_host("http://[::1]:8080"), Some("::1"));
    }

    #[test]
    fn test_extract_origin_host_no_port() {
        assert_eq!(extract_origin_host("http://10.0.0.1"), Some("10.0.0.1"));
        assert_eq!(extract_origin_host("http://localhost"), Some("localhost"));
    }

    #[test]
    fn test_private_origin_valid_rfc1918() {
        assert!(is_private_origin("http://10.0.0.1:8080"));
        assert!(is_private_origin("http://10.255.255.255:8080"));
        assert!(is_private_origin("https://192.168.1.100:443"));
        assert!(is_private_origin("http://172.16.0.1:8080"));
        assert!(is_private_origin("http://172.31.255.255:8080"));
        assert!(is_private_origin("http://127.0.0.1:3000"));
        assert!(is_private_origin("http://localhost:8080"));
    }

    #[test]
    fn test_private_origin_rejects_malicious_domains() {
        // Domain names starting with private IP prefixes must be rejected
        assert!(!is_private_origin("http://10.malware.net:8080"));
        assert!(!is_private_origin("http://192.168.evil.com:8080"));
        assert!(!is_private_origin("http://172.16.attack.org:8080"));
        assert!(!is_private_origin("http://10.0.0.1.evil.com:8080"));
    }

    #[test]
    fn test_private_origin_rejects_public_ips() {
        assert!(!is_private_origin("http://8.8.8.8:8080"));
        assert!(!is_private_origin("http://1.1.1.1:443"));
        assert!(!is_private_origin("http://172.32.0.1:8080")); // just outside 172.16-31
        assert!(!is_private_origin("http://172.15.0.1:8080")); // just below 172.16
    }

    #[test]
    fn test_private_origin_rejects_garbage() {
        assert!(!is_private_origin(""));
        assert!(!is_private_origin("ftp://10.0.0.1"));
        assert!(!is_private_origin("not-a-url"));
    }

    #[test]
    fn test_private_origin_ipv6_loopback() {
        assert!(is_private_origin("http://[::1]:8080"));
    }
}
