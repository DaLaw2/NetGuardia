use crate::domain::common::error::Error;

/// Port for plaintext access to sensitive values (e.g. SMTP password, JWT
/// secret). The adapter (`infrastructure/secret_store.rs`) wraps
/// `ConfigRepo::get_app_secret` / `set_app_secret` with AES-256-GCM
/// envelope encryption, so callers of this port never see ciphertext.
#[async_trait::async_trait]
pub trait SecretStorePort: Send + Sync {
    async fn get_secret(&self, key: &str) -> Result<Option<String>, Error>;
    async fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
    fn encrypt_envelope(&self, plaintext: &str) -> Result<String, Error>;
}
