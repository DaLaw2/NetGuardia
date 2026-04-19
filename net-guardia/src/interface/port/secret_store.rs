use crate::model::error::Error;

/// Port for plaintext access to sensitive values (e.g. SMTP password, JWT
/// secret). The adapter (`infrastructure/secret_store.rs`) wraps
/// `SettingRepo::get_app_secret` / `set_app_secret` with AES-256-GCM
/// envelope encryption, so callers of this port never see ciphertext.
pub trait SecretStorePort: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
}
