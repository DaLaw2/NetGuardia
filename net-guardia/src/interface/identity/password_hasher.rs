use crate::common::error::Error;

pub trait PasswordHasher: Send + Sync {
    fn hash_password(&self, password: &str) -> Result<String, Error>;
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error>;
}
