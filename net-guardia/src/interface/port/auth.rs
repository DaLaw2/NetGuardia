use crate::model::error::Error;

/// Claims extracted from a validated JWT token.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    pub sub: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub exp: usize,
}

/// Port for authentication operations.
/// Adapters: JWT (current), could be OAuth, etc.
pub trait AuthPort: Send + Sync {
    fn create_token(&self, user_id: i64, username: &str, role: &str, permissions: Vec<String>) -> Result<String, Error>;
    fn validate_token(&self, token: &str) -> Result<TokenClaims, Error>;
    fn hash_password(&self, password: &str) -> Result<String, Error>;
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error>;
}
