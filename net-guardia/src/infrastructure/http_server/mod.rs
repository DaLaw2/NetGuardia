use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use actix_cors::Cors;
use actix_web::dev::{Server, ServerHandle};
use actix_web::web::route;
use actix_web::{App, HttpServer, web};
use macros::log;

use crate::adapter::http::default;
use crate::adapter::http::middleware::https_redirect::HttpsRedirect;
use crate::adapter::http::middleware::setup_guard::SetupGuard;
use crate::adapter::http::ready;
use crate::adapter::http::session::SessionCookieService;
use crate::adapter::http::setup::SetupToken;
use crate::adapter::persistence::Database;
use crate::adapter::secret_store::SecretStore;
use crate::adapter::websocket::routes;
use crate::common::error::Error;
use crate::common::error::http::HttpError;
use crate::common::log::http::HttpLog;
use crate::core::common::setup_service::SetupService;
use crate::core::identity::auth_service::AuthService;
use crate::core::identity::session_service::SessionService;
use crate::domain::common::config::constants::HTTP_FALLBACK_PORT;
use crate::infrastructure::http_runtime::{ForceHttpsFlag, ReadyFlag, SetupCompleteFlag};
use crate::infrastructure::log_buffer::LogBuffer;
use crate::infrastructure::logger::Logger;
use crate::infrastructure::startup::SystemRuntime;
use crate::infrastructure::system::ShutdownHandle;
use crate::interface::data_plane::drop_stats::DropStatsPort;
use crate::interface::data_plane::protocol_filter::HttpFilterPort;
use crate::interface::data_plane::protocol_filter::SshFilterPort;
use crate::interface::identity::api_key::ApiKeyRepo;
use crate::interface::identity::api_key_hasher::ApiKeyHasher;
use crate::interface::identity::auth_repo::LoginAttemptRepo;
use crate::interface::system::audit::AuditRepo;
use crate::interface::system::health_query::{HealthQuery, SuricataHealthQuery};
use crate::interface::system::http_runtime::ReadinessQuery;
use crate::interface::system::live_logs::LiveLogQuery;
use crate::interface::system::system_control::{LogLevelControl, SystemCommandPort, XdpModeQuery};

mod api_routes;

pub struct HttpServerParams<'a> {
    pub runtime: &'a SystemRuntime,
    pub logger: Arc<Logger>,
    pub log_buffer: Arc<LogBuffer>,
    pub setup_complete: SetupCompleteFlag,
    pub ready: ReadyFlag,
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
        return octets[0] == 127
            || octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168);
    }

    if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        let octets = ipv6.octets();
        return ipv6.is_loopback() || (octets[0] & 0xfe) == 0xfc || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80);
    }

    false
}

pub struct SetupServerParams {
    pub database: Arc<Database>,
    pub secret_store: Arc<SecretStore>,
    pub setup_service: Arc<SetupService>,
    pub session_service: Arc<SessionService>,
    pub session_cookie_service: Arc<SessionCookieService>,
    pub auth_service: Arc<AuthService>,
    pub api_key_hasher: Arc<dyn ApiKeyHasher>,
    pub setup_complete: SetupCompleteFlag,
    pub setup_token: SetupToken,
    pub port: u16,
}

pub fn start_setup_server(params: SetupServerParams) -> Result<ServerHandle, Error> {
    let database = params.database;
    let secret_store = params.secret_store;
    let setup_service = params.setup_service;
    let session_service = params.session_service;
    let session_cookie_service = params.session_cookie_service;
    let auth_service = params.auth_service;
    let api_key_hasher = params.api_key_hasher;
    let setup_complete = params.setup_complete;
    let setup_token = params.setup_token;
    let port = params.port;

    let app = move || {
        App::new()
            .wrap(cors(vec![]))
            .app_data(web::Data::from(database.clone() as Arc<dyn LoginAttemptRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn ApiKeyRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn AuditRepo>))
            .app_data(web::Data::from(api_key_hasher.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(setup_service.clone()))
            .app_data(web::Data::from(session_service.clone()))
            .app_data(web::Data::from(session_cookie_service.clone()))
            .app_data(web::Data::from(auth_service.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .app_data(web::Data::new(setup_token.clone()))
            .configure(api_routes::configure_setup_api)
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

pub fn bind(params: HttpServerParams<'_>) -> Result<Server, Error> {
    let runtime = params.runtime;
    let app_config = runtime.foundation.app_config.clone();
    let runtime_state = runtime.foundation.runtime_state.clone();
    let inference_config = runtime.detection.inference_config.clone();

    let database = runtime.foundation.database.clone();
    let secret_store = runtime.foundation.secret_store.clone();
    let logger = params.logger;
    let log_buffer = params.log_buffer;

    let access_control = runtime.data_plane.ebpf_services.access_control.clone();
    let http_filter: Arc<dyn HttpFilterPort> = runtime.data_plane.ebpf_services.protocol_filter.clone();
    let ssh_filter: Arc<dyn SshFilterPort> = runtime.data_plane.ebpf_services.protocol_filter.clone();
    let geo_block = runtime.data_plane.ebpf_services.geo_block.clone();
    let rate_limit = runtime.data_plane.ebpf_services.rate_limit.clone();
    let drop_monitor = runtime.data_plane.ebpf_services.drop_monitor.clone();
    let drop_stats: Arc<dyn DropStatsPort> = drop_monitor.clone();
    let ml_alert = runtime.detection.inference_runtime.ml_alert.clone();
    let ml_engine = runtime.detection.inference_runtime.ml_engine.clone();
    let ml_inference = runtime.detection.inference_runtime.ml_inference.clone();
    let fusion_metrics = runtime.detection.inference_runtime.fusion_metrics.clone();
    let health = runtime.observability.health.clone();
    let flow_statistics = runtime.detection.flow_statistics.clone();

    let session_service = runtime.identity.session_service.clone();
    let session_cookie_service = runtime.identity.session_cookie_service.clone();
    let auth_service = runtime.identity.auth_service.clone();
    let user_service = runtime.identity.user_service.clone();
    let group_service = runtime.identity.group_service.clone();
    let enforce_handler = runtime.identity.enforce_handler.clone();
    let api_key_hasher = runtime.identity.api_key_hasher.clone();

    let acl_service = runtime.response.acl_service.clone();
    let config_service = runtime.response.config_service.clone();
    let dns_filter_service = runtime.response.dns_filter_service.clone();
    let notification_service = runtime.response.notification_service.clone();
    let playbook_service = runtime.response.playbook_service.clone();
    let rate_limit_service = runtime.response.rate_limit_service.clone();
    let soar_engine = runtime.response.soar_engine.clone();
    let report_generation_service = runtime.reporting.report_generation_service.clone();
    let report_delivery_service = runtime.reporting.report_delivery_service.clone();
    let suricata_manager = runtime.observability.suricata_manager.clone();

    let threat_tx = runtime.foundation.channels.threat_tx.clone();
    let audit_tx = runtime.foundation.channels.audit_tx.clone();

    let setup_complete = params.setup_complete;
    let ready = params.ready;
    let readiness_state = runtime.foundation.readiness.clone();
    let force_https = params.force_https;
    let shutdown_handle = params.shutdown_handle;

    let setup_service = runtime.foundation.setup_service.clone();
    let boot_time_query = runtime.foundation.boot_time_query.clone();
    let promote_gate = runtime.detection.promote_gate.clone();
    let model_promotion_deps = runtime.detection.model_promotion_deps.clone();

    let port = app_config.load().http_server.port;

    let server = HttpServer::new(move || {
        let app = App::new()
            .wrap(HttpsRedirect)
            .wrap(cors(app_config.load().http_server.cors_allowed_origins.clone()))
            .app_data(web::Data::from(app_config.clone()))
            .app_data(web::Data::from(runtime_state.clone() as Arc<dyn XdpModeQuery>))
            .app_data(web::Data::from(inference_config.clone()))
            .app_data(web::Data::from(database.clone() as Arc<dyn LoginAttemptRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn ApiKeyRepo>))
            .app_data(web::Data::from(database.clone() as Arc<dyn AuditRepo>))
            .app_data(web::Data::from(api_key_hasher.clone()))
            .app_data(web::Data::from(secret_store.clone()))
            .app_data(web::Data::from(access_control.clone()))
            .app_data(web::Data::from(http_filter.clone()))
            .app_data(web::Data::from(ssh_filter.clone()))
            .app_data(web::Data::from(geo_block.clone()))
            .app_data(web::Data::from(rate_limit.clone()))
            .app_data(web::Data::from(drop_monitor.clone()))
            .app_data(web::Data::from(drop_stats.clone()))
            .app_data(web::Data::from(ml_alert.clone()))
            .app_data(web::Data::from(ml_engine.clone()))
            .app_data(web::Data::from(ml_inference.clone()))
            .app_data(web::Data::from(fusion_metrics.clone()))
            .app_data(web::Data::from(flow_statistics.clone()))
            .app_data(web::Data::from(promote_gate.clone()))
            .app_data(web::Data::from(model_promotion_deps.clone()))
            .app_data(web::Data::from(session_service.clone()))
            .app_data(web::Data::from(session_cookie_service.clone()))
            .app_data(web::Data::from(auth_service.clone()))
            .app_data(web::Data::from(user_service.clone()))
            .app_data(web::Data::from(group_service.clone()))
            .app_data(web::Data::from(enforce_handler.clone()))
            .app_data(web::Data::from(acl_service.clone()))
            .app_data(web::Data::from(config_service.clone()))
            .app_data(web::Data::from(dns_filter_service.clone()))
            .app_data(web::Data::from(notification_service.clone()))
            .app_data(web::Data::from(playbook_service.clone()))
            .app_data(web::Data::from(rate_limit_service.clone()))
            .app_data(web::Data::from(soar_engine.clone()))
            .app_data(web::Data::from(report_generation_service.clone()))
            .app_data(web::Data::from(report_delivery_service.clone()))
            .app_data(web::Data::from(health.clone() as Arc<dyn HealthQuery>))
            .app_data(web::Data::from(suricata_manager.clone() as Arc<dyn SuricataHealthQuery>))
            .app_data(web::Data::from(logger.clone() as Arc<dyn LogLevelControl>))
            .app_data(web::Data::from(log_buffer.clone() as Arc<dyn LiveLogQuery>))
            .app_data(web::Data::from(setup_service.clone()))
            .app_data(web::Data::from(boot_time_query.clone()))
            .app_data(web::Data::new(setup_complete.clone()))
            .app_data(web::Data::new(ready.clone()))
            .app_data(web::Data::from(readiness_state.clone() as Arc<dyn ReadinessQuery>))
            .app_data(web::Data::new(force_https.clone()))
            .app_data(web::Data::from(shutdown_handle.clone() as Arc<dyn SystemCommandPort>))
            .app_data(web::Data::new(threat_tx.clone()))
            .app_data(web::Data::new(audit_tx.clone()));
        app.wrap(SetupGuard)
            .configure(api_routes::configure_authenticated_api)
            .service(routes::initialize())
            .route("/health/ready", web::get().to(ready::health_ready))
            .default_service(route().to(default::default_route))
    })
    .bind(format!("0.0.0.0:{}", port))
    .map_err(HttpError::BindPortError)?
    .run();
    Ok(server)
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
        assert!(!is_private_origin("http://10.malware.net:8080"));
        assert!(!is_private_origin("http://192.168.evil.com:8080"));
        assert!(!is_private_origin("http://172.16.attack.org:8080"));
        assert!(!is_private_origin("http://10.0.0.1.evil.com:8080"));
    }

    #[test]
    fn test_private_origin_rejects_public_ips() {
        assert!(!is_private_origin("http://8.8.8.8:8080"));
        assert!(!is_private_origin("http://1.1.1.1:443"));
        assert!(!is_private_origin("http://172.32.0.1:8080"));
        assert!(!is_private_origin("http://172.15.0.1:8080"));
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

    #[test]
    fn test_private_origin_ipv6_private_ranges() {
        assert!(is_private_origin("http://[fc00::1]:8080"));
        assert!(is_private_origin("http://[fd12:3456::1]:8080"));
        assert!(is_private_origin("http://[fe80::1]:8080"));
        assert!(is_private_origin("http://[febf::1]:8080"));
        assert!(!is_private_origin("http://[2001:4860:4860::8888]:8080"));
        assert!(!is_private_origin("http://[fec0::1]:8080"));
    }
}
