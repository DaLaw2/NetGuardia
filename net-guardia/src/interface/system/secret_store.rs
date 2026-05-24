use crate::common::error::Error;

#[async_trait::async_trait]
pub trait SecretStorePort: Send + Sync {
    async fn get_secret(&self, key: &str) -> Result<Option<String>, Error>;
    async fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
    fn encrypt_envelope(&self, plaintext: &str) -> Result<String, Error>;
}
