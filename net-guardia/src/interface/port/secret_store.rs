use crate::model::error::Error;

pub trait SecretStorePort: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<String>, Error>;
    fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error>;
}
