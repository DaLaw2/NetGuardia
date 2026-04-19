use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, errors::ErrorKind};

use crate::interface::port::secret_store::SecretStorePort;
use crate::model::error::Error;
use crate::model::error::auth::AuthError;
use crate::model::identity::auth::Claims;

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_hours: u64,
}

impl JwtService {
    /// Generate a fresh random JWT signing secret on every boot.
    /// This intentionally invalidates all existing tokens on restart.
    pub fn new(_secrets: &Arc<dyn SecretStorePort>, expiry_hours: u64) -> Result<Self, Error> {
        use rand::Rng;
        let secret: [u8; 32] = rand::rng().random();

        Ok(Self {
            encoding_key: EncodingKey::from_secret(&secret),
            decoding_key: DecodingKey::from_secret(&secret),
            expiry_hours,
        })
    }

    pub fn create_token(
        &self,
        user_id: i64,
        username: &str,
        role: &str,
        permissions: Vec<String>,
    ) -> Result<String, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            role: role.to_string(),
            permissions,
            exp: (now + self.expiry_hours * 3600) as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key).map_err(|_| AuthError::InvalidToken.into())
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        let token_data =
            decode::<Claims>(token, &self.decoding_key, &Validation::new(Algorithm::HS256)).map_err(|e| {
                match e.kind() {
                    ErrorKind::ExpiredSignature => Error::from(AuthError::TokenExpired),
                    _ => Error::from(AuthError::InvalidToken),
                }
            })?;
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;
    use crate::infrastructure::secret_store::SecretStore;

    fn test_jwt_service() -> JwtService {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let secrets: Arc<dyn SecretStorePort> = Arc::new(SecretStore::new(db));
        JwtService::new(&secrets, 24).unwrap()
    }

    #[test]
    fn test_create_and_validate_token() {
        let jwt = test_jwt_service();
        let perms = vec!["dashboard:read".to_string()];
        let token = jwt.create_token(1, "admin", "admin", perms.clone()).unwrap();
        let claims = jwt.validate_token(&token).unwrap();
        assert_eq!(claims.sub, 1);
        assert_eq!(claims.username, "admin");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.permissions, perms);
    }

    #[test]
    fn test_invalid_token() {
        let jwt = test_jwt_service();
        let result = jwt.validate_token("invalid.token.here");
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_token() {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let secrets: Arc<dyn SecretStorePort> = Arc::new(SecretStore::new(db));
        let jwt = JwtService::new(&secrets, 0).unwrap(); // 0 hours = immediate expiry

        // Create token with 0 hour expiry — it expires in the past
        let claims = Claims {
            sub: 1,
            username: "admin".to_string(),
            role: "admin".to_string(),
            permissions: vec![],
            exp: 0, // epoch = expired
        };
        let token = encode(&Header::default(), &claims, &jwt.encoding_key).unwrap();
        let result = jwt.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_secret_changes_on_new_instance() {
        let db = Arc::new(Database::new(":memory:").unwrap());
        let secrets: Arc<dyn SecretStorePort> = Arc::new(SecretStore::new(db));

        let jwt1 = JwtService::new(&secrets, 24).unwrap();
        let token = jwt1.create_token(1, "admin", "admin", vec![]).unwrap();

        // New instance = new secret = old token invalid (simulates restart)
        let jwt2 = JwtService::new(&secrets, 24).unwrap();
        let result = jwt2.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_secrets_reject() {
        let jwt1 = test_jwt_service();
        let jwt2 = test_jwt_service(); // different in-memory DB = different secret

        let token = jwt1.create_token(1, "admin", "admin", vec![]).unwrap();
        let result = jwt2.validate_token(&token);
        assert!(result.is_err());
    }
}
