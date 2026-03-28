use std::sync::atomic::Ordering;
use actix_web::{web, HttpResponse, Scope};
use serde::Deserialize;

use macros::log;

use crate::adapter::persistence::Database;
use crate::core::auth::password;
use crate::core::auth::setup_guard::SetupCompleteFlag;
use crate::model::error::system::SystemError;

pub fn initialize() -> Scope {
    web::scope("/setup")
        .route("/status", web::get().to(setup_status))
        .route("/interfaces", web::get().to(list_interfaces))
        .route("/complete", web::post().to(complete_setup))
}

async fn setup_status(
    setup_flag: web::Data<SetupCompleteFlag>,
) -> HttpResponse {
    let complete = setup_flag.load(Ordering::SeqCst);
    HttpResponse::Ok().json(serde_json::json!({
        "setup_complete": complete,
    }))
}

async fn list_interfaces() -> HttpResponse {
    // List available network interfaces
    let interfaces: Vec<serde_json::Value> = match std::fs::read_dir("/sys/class/net") {
        Ok(entries) => {
            entries
                .filter_map(|e| e.ok())
                .map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    serde_json::json!({
                        "name": name,
                        "is_loopback": name == "lo",
                    })
                })
                .collect()
        }
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
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

async fn complete_setup(
    db: web::Data<Database>,
    setup_flag: web::Data<SetupCompleteFlag>,
    body: web::Json<SetupRequest>,
) -> HttpResponse {
    // Check if already completed (concurrent access protection)
    if setup_flag.load(Ordering::SeqCst) {
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
        if !std::path::Path::new(&iface_path).exists() {
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
    if let Err(e) = save_config(&db, &body) {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to save configuration: {}", e)
        }));
    }

    // Update admin password
    match password::hash_password(&body.admin_password) {
        Ok(hash) => {
            // Find admin user and update password
            if let Ok(Some(user)) = db.find_user("admin") {
                if let Err(e) = db.update_user_password(user.0, &hash) {
                    log!(SystemError::SetupPasswordUpdateFailed(e));
                }
                // Clear force_password_change since setup wizard set the password
                if let Err(e) = db.reset_user_password(user.0, &hash) {
                    log!(SystemError::SetupPasswordUpdateFailed(e));
                }
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to hash password: {}", e)
            }));
        }
    }

    // Mark setup as complete
    if let Err(e) = db.set_setting("setup_complete", "true") {
        log!(SystemError::SetupCompleteFlagFailed(e));
    }
    setup_flag.store(true, Ordering::SeqCst);

    // System::run() polls the setup_complete flag and will automatically
    // start eBPF, ML, and SOAR services once this flag becomes true.

    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "setup_complete": true,
        "message": "Setup complete. System is initializing services..."
    }))
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

fn save_config(db: &Database, req: &SetupRequest) -> Result<(), crate::model::error::Error> {
    // Save network config
    db.set_setting("ingress_interface", &req.ingress_interface)?;
    db.set_setting("egress_interface", &req.egress_interface)?;

    if let Some(port) = req.http_port {
        db.set_setting("http_port", &port.to_string())?;
    }

    // Save SMTP config
    if let Some(host) = &req.smtp_host {
        db.set_setting("smtp_host", host)?;
    }
    if let Some(port) = req.smtp_port {
        db.set_setting("smtp_port", &port.to_string())?;
    }
    if let Some(user) = &req.smtp_username {
        db.set_setting("smtp_username", user)?;
    }
    if let Some(pass) = &req.smtp_password {
        db.set_setting("smtp_password", pass)?;
    }
    if let Some(recipient) = &req.smtp_recipient {
        db.set_setting("smtp_recipient", recipient)?;
    }

    // Save Telegram config
    if let (Some(token), Some(chat_id)) = (&req.telegram_bot_token, &req.telegram_chat_id) {
        let config_json = serde_json::json!({
            "bot_token": token,
            "chat_id": chat_id,
        }).to_string();
        db.set_notification_config("telegram", &config_json)?;
    }

    Ok(())
}
