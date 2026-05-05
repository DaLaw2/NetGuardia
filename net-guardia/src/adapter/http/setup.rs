use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;

use actix_web::{HttpResponse, Scope, web};
use macros::log;
use serde::Deserialize;
use serde_json::Value;

use crate::adapter::persistence::Database;
use crate::domain::common::error::Error;
use crate::domain::common::error::system::SystemError;
use crate::domain::identity::auth::DEFAULT_ADMIN_USERNAME;
use crate::domain::identity::password;
use crate::infrastructure::http_server::SetupCompleteFlag;
use crate::infrastructure::secret_store::SecretStore;
use crate::interface::secret_store::SecretStorePort;
use crate::interface::system_state::SystemStateRepo;

pub fn initialize() -> Scope {
    web::scope("/setup")
        .route("/status", web::get().to(setup_status))
        .route("/interfaces", web::get().to(list_interfaces))
        .route("/complete", web::post().to(complete_setup))
}

async fn setup_status(setup_flag: web::Data<SetupCompleteFlag>) -> HttpResponse {
    let complete = setup_flag.0.load(Ordering::SeqCst);
    HttpResponse::Ok().json(serde_json::json!({
        "setup_complete": complete,
    }))
}

async fn list_interfaces() -> HttpResponse {
    // List available network interfaces
    let interfaces: Vec<Value> = match fs::read_dir("/sys/class/net") {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                serde_json::json!({
                    "name": name,
                    "is_loopback": name == "lo",
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    HttpResponse::Ok().json(serde_json::json!({
        "interfaces": interfaces,
    }))
}

#[derive(Deserialize)]
struct SetupRequest {
    /// Ingress network interface (external-facing)
    ingress_interface: String,
    /// Egress network interface (internal-facing)
    egress_interface: String,
    /// Admin password
    admin_password: String,
    /// HTTP port (optional, default 8080)
    http_port: Option<u16>,
    /// SMTP config (optional)
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    smtp_recipient: Option<String>,
    /// Telegram config (optional)
    telegram_bot_token: Option<String>,
    telegram_chat_id: Option<String>,
}

/// Validate interface name: only alphanumeric, dots, underscores, hyphens allowed.
/// Prevents path traversal via crafted interface names like "../../etc/shadow".
fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 16
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

async fn complete_setup(
    db: web::Data<Database>,
    secret_store: web::Data<SecretStore>,
    setup_flag: web::Data<SetupCompleteFlag>,
    body: web::Json<SetupRequest>,
) -> HttpResponse {
    if setup_flag.0.load(Ordering::SeqCst) {
        return HttpResponse::Conflict().json(serde_json::json!({
            "error": "Setup already completed"
        }));
    }

    // Validate interface names (prevent path traversal)
    for iface in [&body.ingress_interface, &body.egress_interface] {
        if !is_valid_interface_name(iface) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Invalid interface name '{}': only alphanumeric, dots, underscores, hyphens allowed (max 16 chars)", iface)
            }));
        }
        let iface_path = format!("/sys/class/net/{}", iface);
        if !Path::new(&iface_path).exists() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("Network interface '{}' not found", iface)
            }));
        }
    }

    // Validate ingress != egress
    if body.ingress_interface == body.egress_interface {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Ingress and egress interfaces must be different"
        }));
    }

    // Validate password strength: min 8 chars, must contain letter + digit + symbol
    let pw = &body.admin_password;
    if pw.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must be at least 8 characters"
        }));
    }
    let has_letter = pw.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_ascii_alphanumeric());
    if !has_letter || !has_digit || !has_symbol {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password must contain at least one letter, one digit, and one symbol"
        }));
    }

    // Save configuration to database
    if let Err(e) = save_config(&db, secret_store.as_ref(), &body).await {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save configuration: {}", e)
        }));
    }

    // Update admin password
    match password::hash_password(&body.admin_password) {
        Ok(hash) => {
            // Find admin user and update password
            if let Ok(Some(user)) = db.find_user(DEFAULT_ADMIN_USERNAME).await
                && let Err(e) = db.update_user_password(user.id, &hash).await
            {
                log!(SystemError::SetupPasswordUpdateFailed(e));
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to hash password: {}", e)
            }));
        }
    }

    // Mark setup as complete
    let state_repo = db.get_ref() as &dyn SystemStateRepo;
    if let Err(e) = state_repo.set_system_state("setup_complete", "true").await {
        log!(SystemError::SetupCompleteFlagFailed(e));
    }
    setup_flag.0.store(true, Ordering::SeqCst);

    // System::run() polls the setup_complete flag and will automatically
    // start eBPF, ML, and SOAR services once this flag becomes true.

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "setup_complete": true,
        "message": "Setup complete. System is initializing services..."
    }))
}

async fn save_config(db: &Database, secrets: &dyn SecretStorePort, req: &SetupRequest) -> Result<(), Error> {
    // Save network config
    db.set_config_value("ingress_interface", &req.ingress_interface).await?;
    db.set_config_value("egress_interface", &req.egress_interface).await?;

    if let Some(port) = req.http_port {
        db.set_config_value("http_port", &port.to_string()).await?;
    }

    // Save SMTP config (non-secret fields go to settings)
    if let Some(host) = &req.smtp_host {
        db.set_config_value("smtp_host", host).await?;
    }
    if let Some(port) = req.smtp_port {
        db.set_config_value("smtp_port", &port.to_string()).await?;
    }
    if let Some(user) = &req.smtp_username {
        db.set_config_value("smtp_username", user).await?;
    }
    if let Some(pass) = &req.smtp_password {
        // Store password through secret store (encrypted)
        secrets.set_secret("smtp_password", pass).await?;
        db.set_config_value("smtp_password", "__encrypted__").await?;
    }
    if let Some(recipient) = &req.smtp_recipient {
        db.set_config_value("smtp_recipient", recipient).await?;
    }

    // Save Telegram config (bot_token through secret store, chat_id in JSON)
    if let (Some(token), Some(chat_id)) = (&req.telegram_bot_token, &req.telegram_chat_id) {
        secrets.set_secret("telegram_bot_token", token).await?;
        let config_json = serde_json::json!({
            "bot_token": "__encrypted__",
            "chat_id": chat_id,
        })
        .to_string();
        db.set_notification_config("telegram", &config_json).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
        // Exactly 16 should be valid
        let exact = "a".repeat(16);
        assert!(is_valid_interface_name(&exact));
    }

    #[test]
    fn test_invalid_interface_path_traversal() {
        assert!(!is_valid_interface_name("../etc"));
        assert!(!is_valid_interface_name("../../shadow"));
        assert!(!is_valid_interface_name("/sys/class"));
    }

    #[test]
    fn test_invalid_interface_special_chars() {
        assert!(!is_valid_interface_name("eth0;rm"));
        assert!(!is_valid_interface_name("lo&&cat"));
        assert!(!is_valid_interface_name("eth0 space"));
    }
}
