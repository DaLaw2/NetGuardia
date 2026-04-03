use std::sync::Arc;

use actix_web::web::route;
use actix_web::{App, HttpServer, web};

use crate::adapter::http::{
    acl, api_keys, audit as audit_api, auth, default, filter, health as health_api, logs as logs_api, ml,
    notification as notification_api, rate_limit as rate_limit_api, report as report_api, setup as setup_api, soar,
    stats, system as system_api,
};
use crate::adapter::persistence::Database;
use crate::adapter::websocket::routes as ws;
use crate::core::acl_service::AclService;
use crate::core::auth::https_redirect::{ForceHttpsFlag, HttpsRedirect};
use crate::core::auth::jwt::JwtService;
use crate::core::auth::setup_guard::{SetupCompleteFlag, SetupGuard};
use crate::core::config_service::ConfigService;
use crate::core::dns_filter_service::DnsFilterService;
use crate::core::ebpf::EbpfServices;
use crate::core::ml::config_loader::InferenceConfig;
use crate::core::notification_service::NotificationService;
use crate::core::playbook_service::PlaybookService;
use crate::core::rate_limit_service::RateLimitService;
use crate::core::system::ShutdownHandle;
use crate::infrastructure::app_config::AppConfig;
use crate::infrastructure::app_services::AppServices;
use crate::infrastructure::communication_manager::CommunicationManager;
use crate::infrastructure::secret_store::SecretStore;
use crate::interface::port::api_key::ApiKeyPort;
use crate::interface::port::repository::RepositoryPort;
use crate::model::config::constants::HTTP_FALLBACK_PORT;
use crate::model::error::Error;
use crate::model::error::http::HttpError;
use crate::model::log::http::HttpLog;
use macros::log;

/// Shared flag: true when all services (eBPF, ML, SOAR) are fully initialized.
pub type ReadyFlag = Arc<std::sync::atomic::AtomicBool>;

use crate::model::system::readiness::ReadinessState;

/// Parameters for starting the HTTP server, avoiding `#[cfg]` on function params.
pub struct HttpServerParams {
    pub app_config: Arc<AppConfig>,
    pub inference_config: Arc<InferenceConfig>,
    pub ebpf_services: Arc<EbpfServices>,
    pub app_services: Arc<AppServices>,
    pub db: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub jwt_service: Arc<JwtService>,
    pub comm: Arc<CommunicationManager>,
    pub setup_complete: SetupCompleteFlag,
    pub ready: ReadyFlag,
    pub readiness_state: Arc<ReadinessState>,
    pub acl_service: Arc<AclService>,
    pub config_service: Arc<ConfigService>,
    pub dns_filter_service: Arc<DnsFilterService>,
    pub notification_service: Arc<NotificationService>,
    pub playbook_service: Arc<PlaybookService>,
    pub rate_limit_service: Arc<RateLimitService>,
    pub force_https: ForceHttpsFlag,
    pub shutdown_handle: Arc<ShutdownHandle>,
}

/// CORS configuration shared by both full and setup servers.
///
/// When `allowed_origins` is non-empty, only those exact origins are permitted.
/// When empty, RFC 1918 private-network origins (localhost, 127.0.0.1,
/// 192.168.x.x, 10.x.x.x, 172.16-31.x.x) are allowed.
///
/// The host is parsed as an IP address — domain names like "10.malware.net"
/// are rejected because they fail IP parsing.
fn cors(allowed_origins: Vec<String>) -> actix_cors::Cors {
    actix_cors::Cors::default()
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

/// Extract the host portion from an origin string like "http://10.0.0.1:8080".
/// Returns the host without scheme or port.
fn extract_origin_host(origin: &str) -> Option<&str> {
    // Strip scheme
    let after_scheme = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    // Strip port (if present) — find last colon that isn't part of IPv6
    // For IPv6 origins like http://[::1]:8080, strip brackets too
    if after_scheme.starts_with('[') {
        // IPv6 bracket notation: [::1]:8080
        let bracket_end = after_scheme.find(']')?;
        Some(&after_scheme[1..bracket_end])
    } else {
        // IPv4 or hostname: split at last colon for port
        Some(after_scheme.split(':').next().unwrap_or(after_scheme))
    }
}

/// Check if an origin URL points to a RFC 1918 private network address or localhost.
/// Only accepts actual IP addresses — domain names are rejected.
fn is_private_origin(origin: &str) -> bool {
    let host = match extract_origin_host(origin) {
        Some(h) => h,
        None => return false,
    };

    if host == "localhost" {
        return true;
    }

    // Try parsing as IPv4
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        let octets = ipv4.octets();
        return octets[0] == 127                                         // 127.0.0.0/8
            || octets[0] == 10                                          // 10.0.0.0/8
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))     // 172.16.0.0/12
            || (octets[0] == 192 && octets[1] == 168); // 192.168.0.0/16
    }

    // Try parsing as IPv6
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return ipv6.is_loopback();
    }

    // Not a valid IP address (e.g. "10.malware.net") — reject
    false
}

/// Minimal HTTP server for setup wizard mode.
/// Only serves setup, auth, and health routes — no eBPF/ML dependencies.
/// Returns a ServerHandle so the caller can stop it after setup completes.
pub fn start_setup_server(
    db: Arc<Database>,
    secret_store: Arc<SecretStore>,
    jwt_service: Arc<JwtService>,
    setup_complete: SetupCompleteFlag,
    port: u16,
) -> Result<actix_web::dev::ServerHandle, Error> {
    let make_app = move || {
        App::new()
            .wrap(cors(vec![]))
            .app_data(web::Data::from(db.clone() as Arc<dyn RepositoryPort>))
            .app_data(web::Data::from(db.clone() as Arc<dyn ApiKeyPort>))
            .app_data(web::Data::from(db.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .service(
                web::scope("/api")
                    .wrap(crate::core::auth::middleware::AuthMiddleware)
                    .service(auth::initialize())
                    .service(setup_api::initialize())
                    .service(health_api::initialize()),
            )
            .default_service(route().to(default::default_route))
    };

    let server = match HttpServer::new(make_app.clone())
        .workers(1)
        .shutdown_timeout(1) // Fast shutdown — no long-lived connections to drain
        .bind(format!("0.0.0.0:{}", port))
    {
        Ok(s) => s,
        Err(e) if port != HTTP_FALLBACK_PORT => {
            log!(HttpLog::SetupBindFallback(port, e.to_string(), HTTP_FALLBACK_PORT));
            HttpServer::new(make_app)
                .workers(1)
                .shutdown_timeout(1)
                .bind(format!("0.0.0.0:{}", HTTP_FALLBACK_PORT))
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
    let secret_store = params.secret_store;
    let jwt_service = params.jwt_service;
    let comm = params.comm;
    let setup_complete = params.setup_complete;
    let ready = params.ready;
    let readiness_state = params.readiness_state;
    let acl_service = params.acl_service;
    let config_service = params.config_service;
    let dns_filter_service = params.dns_filter_service;
    let notification_service = params.notification_service;
    let playbook_service = params.playbook_service;
    let rate_limit_service = params.rate_limit_service;
    let force_https = params.force_https;
    let shutdown_handle = params.shutdown_handle;
    let port = app_config.http.http_server_bind_port;

    HttpServer::new(move || {
        let app = App::new()
            .wrap(HttpsRedirect)
            .wrap(cors(app_config.http.cors_allowed_origins.clone()))
            .app_data(web::Data::new(force_https.clone()))
            .app_data(web::Data::from(shutdown_handle.clone()))
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
            .app_data(web::Data::from(db.clone() as Arc<dyn ApiKeyPort>))
            .app_data(web::Data::from(db.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(jwt_service.clone()))
            .app_data(web::Data::from(comm.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .app_data(web::Data::new(ready.clone()))
            .app_data(web::Data::from(readiness_state.clone()))
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
                    .service(api_keys::initialize())
                    .service(logs_api::initialize())
                    .service(audit_api::initialize())
                    .service(setup_api::initialize()),
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

async fn health_ready(ready: web::Data<ReadyFlag>, state: web::Data<ReadinessState>) -> actix_web::HttpResponse {
    use std::sync::atomic::Ordering::SeqCst;

    let is_ready = ready.load(SeqCst);
    let uptime_secs = state.started_at.elapsed().as_secs();

    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "ready": is_ready,
        "subsystems": {
            "db_connected": state.db_connected.load(SeqCst),
            "ml_model_loaded": state.ml_model_loaded.load(SeqCst),
            "soar_engine_running": state.soar_engine_running.load(SeqCst),
            "ebpf_attached": state.ebpf_attached.load(SeqCst),
        },
        "uptime_secs": uptime_secs,
    }))
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
