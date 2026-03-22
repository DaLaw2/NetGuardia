use jsonwebtoken::{decode, encode, errors::ErrorKind, DecodingKey, EncodingKey, Header, Validation};

use crate::interface::port::repository::RepositoryPort;
use crate::model::auth::Claims;
use crate::model::error::auth::AuthError;
use crate::model::error::Error;

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_hours: u64,
}

impl JwtService {
    pub fn new(db: &dyn RepositoryPort, expiry_hours: u64) -> Result<Self, Error> {
        let secret = match db.get_setting("jwt_secret")? {
            Some(s) => s,
            None => {
                use rand::Rng;
                let secret: Vec<u8> = rand::rng().random::<[u8; 32]>().to_vec();
                let encoded = hex_encode(&secret);
                db.set_setting("jwt_secret", &encoded)?;
                encoded
            }
        };

        let secret_bytes = secret.as_bytes();
        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret_bytes),
            decoding_key: DecodingKey::from_secret(secret_bytes),
            expiry_hours,
        })
    }

    pub fn create_token(&self, user_id: i64, username: &str, role: &str, permissions: Vec<String>) -> Result<String, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            role: role.to_string(),
            permissions,
            exp: (now + self.expiry_hours * 3600) as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::InvalidToken.into())
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| {
                match e.kind() {
                    ErrorKind::ExpiredSignature => Error::from(AuthError::TokenExpired),
                    _ => Error::from(AuthError::InvalidToken),
                }
            })?;
        Ok(token_data.claims)
    }
}

fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::persistence::Database;

    fn test_jwt_service() -> JwtService {
        let db = Database::new(":memory:").unwrap();
        JwtService::new(&db, 24).unwrap()
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
        let db = Database::new(":memory:").unwrap();
        let jwt = JwtService::new(&db, 0).unwrap(); // 0 hours = immediate expiry

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
    fn test_jwt_secret_persistence() {
        let db = Database::new(":memory:").unwrap();

        // First creation generates and stores secret
        let jwt1 = JwtService::new(&db, 24).unwrap();
        let token = jwt1.create_token(1, "admin", "admin", vec![]).unwrap();

        // Second creation reuses stored secret
        let jwt2 = JwtService::new(&db, 24).unwrap();
        let claims = jwt2.validate_token(&token).unwrap();
        assert_eq!(claims.username, "admin");
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
