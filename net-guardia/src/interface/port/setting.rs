use crate::model::error::Error;

/// Configuration technical service — key/value settings, encrypted app secrets,
/// and per-channel notification config blobs.
///
/// Per DOMAIN_MAP §2 this is a Technical Service (no BC), but it has an
/// aggregate-shaped DB footprint (three tables: `settings`, `app_secrets`,
/// `notification_config`) with identical K/V semantics, so it gets a single
/// repo trait rather than three.
#[allow(dead_code)]
pub trait SettingRepo: Send + Sync {
    // --- Plain settings (cleartext K/V) ---
    fn get_setting(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), Error>;

    // --- App secrets (encrypted-at-rest in `app_secrets` table) ---
    fn get_app_secret(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_app_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;

    // --- Notification channel config blobs (JSON) ---
    fn get_notification_config(&self, channel: &str) -> Result<Option<String>, Error>;
    fn set_notification_config(&self, channel: &str, config_json: &str) -> Result<(), Error>;
}
