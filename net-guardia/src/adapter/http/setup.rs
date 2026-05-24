use std::fs;
use std::io;
use std::path::Path;

use actix_web::{HttpRequest, HttpResponse, Scope, web};
use macros::log;
use serde::{Deserialize, Serialize};

use crate::adapter::http::helpers::{bad_request, conflict, internal_error};
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::common::utils::security::constant_time_eq;
use crate::core::common::setup_service::{CompleteSetupInput, SetupService, is_valid_interface_name};
use crate::infrastructure::http_runtime::SetupCompleteFlag;

pub const SETUP_TOKEN_HEADER: &str = "X-Setup-Token";

#[derive(Clone)]
pub struct SetupToken {
    token: String,
}

impl SetupToken {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    fn validate(&self, candidate: &str) -> bool {
        constant_time_eq(&self.token, candidate)
    }
}

pub fn initialize() -> Scope {
    web::scope("/setup")
        .route("/status", web::get().to(setup_status))
        .route("/interfaces", web::get().to(list_interfaces))
        .route("/complete", web::post().to(complete_setup))
}

async fn setup_status(setup_flag: web::Data<SetupCompleteFlag>) -> HttpResponse {
    let complete = setup_flag.is_complete();
    HttpResponse::Ok().json(serde_json::json!({
        "setup_complete": complete,
    }))
}

async fn list_interfaces() -> HttpResponse {
    let interfaces = match list_network_interfaces(Path::new("/sys/class/net")) {
        Ok(interfaces) => interfaces,
        Err(e) => return internal_error(format!("Failed to list network interfaces: {}", e)),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "interfaces": interfaces,
    }))
}

#[derive(Serialize)]
struct NetworkInterface {
    name: String,
    is_loopback: bool,
}

fn list_network_interfaces(interface_dir: &Path) -> io::Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir(interface_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        interfaces.push(NetworkInterface {
            is_loopback: name == "lo",
            name,
        });
    }
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(interfaces)
}

#[derive(Deserialize)]
struct SetupRequest {
    ingress_interface: String,
    egress_interface: String,
    admin_password: String,
    http_port: Option<u16>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    smtp_recipient: Option<String>,
    telegram_bot_token: Option<String>,
    telegram_chat_id: Option<String>,
}

async fn complete_setup(
    req: HttpRequest,
    setup_service: web::Data<SetupService>,
    setup_flag: web::Data<SetupCompleteFlag>,
    setup_token: web::Data<SetupToken>,
    body: web::Json<SetupRequest>,
) -> HttpResponse {
    if setup_flag.is_complete() {
        return conflict("Setup already completed");
    }

    let token = req
        .headers()
        .get(SETUP_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !setup_token.validate(token) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid setup token",
        }));
    }

    for iface in [&body.ingress_interface, &body.egress_interface] {
        if !is_valid_interface_name(iface) {
            return bad_request(format!("Invalid network interface name '{}'", iface));
        }
        if !Path::new("/sys/class/net").join(iface).exists() {
            return bad_request(format!("Network interface '{}' not found", iface));
        }
    }

    if let Err(e) = setup_service.complete_setup(body.into_inner().into()).await {
        log!(SystemError::SetupCompleteFlagFailed(e.to_string()));
        return setup_error_response(e);
    }

    setup_flag.mark_complete();

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "setup_complete": true,
        "message": "Setup complete. System is initializing services..."
    }))
}

impl From<SetupRequest> for CompleteSetupInput {
    fn from(req: SetupRequest) -> Self {
        Self {
            ingress_interface: req.ingress_interface,
            egress_interface: req.egress_interface,
            admin_password: req.admin_password,
            http_port: req.http_port,
            smtp_host: req.smtp_host,
            smtp_port: req.smtp_port,
            smtp_username: req.smtp_username,
            smtp_password: req.smtp_password,
            smtp_recipient: req.smtp_recipient,
            telegram_bot_token: req.telegram_bot_token,
            telegram_chat_id: req.telegram_chat_id,
        }
    }
}

fn setup_error_response(e: Error) -> HttpResponse {
    match &e {
        Error::System(SystemError::SetupAlreadyComplete) => conflict(e),
        Error::System(SystemError::InvalidSetupInput { .. }) => bad_request(e),
        _ => internal_error(format!("Failed to complete setup: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn test_valid_interface_names() {
        assert!(is_valid_interface_name("eth0"));
        assert!(is_valid_interface_name("ens33"));
        assert!(is_valid_interface_name("br-lan"));
        assert!(is_valid_interface_name("wlan0.1"));
    }

    #[test]
    fn test_invalid_interface_empty() {
        assert!(!is_valid_interface_name(""));
    }

    #[test]
    fn test_invalid_interface_too_long() {
        let long = "a".repeat(17);
        assert!(!is_valid_interface_name(&long));
        let exact = "a".repeat(16);
        assert!(is_valid_interface_name(&exact));
    }

    #[test]
    fn test_invalid_interface_path_traversal() {
        assert!(!is_valid_interface_name("../etc"));
        assert!(!is_valid_interface_name("../../shadow"));
        assert!(!is_valid_interface_name("/sys/class"));
        assert!(!is_valid_interface_name("."));
        assert!(!is_valid_interface_name(".."));
    }

    #[test]
    fn test_invalid_interface_special_chars() {
        assert!(!is_valid_interface_name("eth0;rm"));
        assert!(!is_valid_interface_name("lo&&cat"));
        assert!(!is_valid_interface_name("eth0 space"));
    }

    #[test]
    fn missing_interface_dir_is_reported() {
        let path = temp_path("net-guardia-missing-ifaces");

        assert!(list_network_interfaces(&path).is_err());
    }

    #[test]
    fn setup_token_validates_exact_value_only() {
        let token = SetupToken::new("secret-token".to_string());

        assert!(token.validate("secret-token"));
        assert!(!token.validate("secret-token-2"));
        assert!(!token.validate("secret"));
    }

    #[test]
    fn network_interfaces_are_sorted_and_mark_loopback() {
        let dir = temp_path("net-guardia-ifaces");
        fs::create_dir(&dir).unwrap();
        fs::create_dir(dir.join("zeth0")).unwrap();
        fs::create_dir(dir.join("lo")).unwrap();

        let interfaces = list_network_interfaces(&dir).unwrap();

        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name, "lo");
        assert!(interfaces[0].is_loopback);
        assert_eq!(interfaces[1].name, "zeth0");
        assert!(!interfaces[1].is_loopback);
    }

    fn temp_path(prefix: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "{}-{}",
            prefix,
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }
}
