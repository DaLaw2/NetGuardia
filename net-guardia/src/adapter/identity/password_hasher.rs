use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher as Argon2PasswordHasherTrait, PasswordVerifier};

use crate::common::error::Error;
use crate::domain::identity::error::AuthError;
use crate::interface::identity::password_hasher::PasswordHasher;

pub struct Argon2PasswordHasher;

impl PasswordHasher for Argon2PasswordHasher {
    fn hash_password(&self, password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AuthError::InvalidCredentials)?;
        Ok(hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        let parsed = PasswordHash::new(hash).map_err(|_| AuthError::InvalidCredentials)?;
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_verifies_passwords() {
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash_password("mypassword123").unwrap();

        assert!(hasher.verify_password("mypassword123", &hash).unwrap());
        assert!(!hasher.verify_password("wrongpassword", &hash).unwrap());
    }

    #[test]
    fn uses_different_salts_for_same_password() {
        let hasher = Argon2PasswordHasher;
        let hash1 = hasher.hash_password("same").unwrap();
        let hash2 = hasher.hash_password("same").unwrap();

        assert_ne!(hash1, hash2);
        assert!(hasher.verify_password("same", &hash1).unwrap());
        assert!(hasher.verify_password("same", &hash2).unwrap());
    }

    #[test]
    fn invalid_hash_is_an_error() {
        let hasher = Argon2PasswordHasher;
        let result = hasher.verify_password("password", "not-a-valid-hash");

        assert!(result.is_err());
    }
}
