use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::core::database::Database;
use crate::model::error::auth::AuthError;
use crate::model::error::Error;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: i64,
    pub username: String,
    pub role: String,
    pub exp: usize,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    expiry_hours: u64,
}

impl JwtService {
    pub fn new(db: &Database, expiry_hours: u64) -> Result<Self, Error> {
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

    pub fn create_token(&self, user_id: i64, username: &str, role: &str) -> Result<String, Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            sub: user_id,
            username: username.to_string(),
            role: role.to_string(),
            exp: (now + self.expiry_hours * 3600) as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AuthError::InvalidToken.into())
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, Error> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| {
                if e.to_string().contains("ExpiredSignature") {
                    Error::from(AuthError::TokenExpired)
                } else {
                    Error::from(AuthError::InvalidToken)
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
