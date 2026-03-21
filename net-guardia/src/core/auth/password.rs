use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

use crate::model::error::auth::AuthError;
use crate::model::error::Error;

pub fn hash_password(password: &str) -> Result<String, Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AuthError::InvalidCredentials)?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
    let parsed = PasswordHash::new(hash).map_err(|_| AuthError::InvalidCredentials)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let hash = hash_password("mypassword123").unwrap();
        assert!(verify_password("mypassword123", &hash).unwrap());
        assert!(!verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let hash1 = hash_password("same").unwrap();
        let hash2 = hash_password("same").unwrap();
        assert_ne!(hash1, hash2); // different salts
        assert!(verify_password("same", &hash1).unwrap());
        assert!(verify_password("same", &hash2).unwrap());
    }

    #[test]
    fn test_verify_invalid_hash() {
        let result = verify_password("password", "not-a-valid-hash");
        assert!(result.is_err());
    }
}
