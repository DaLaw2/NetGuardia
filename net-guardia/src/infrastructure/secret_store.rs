use std::env;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use macros::log;
use sha2::Sha256;

use crate::adapter::persistence::Database;
use crate::domain::common::error::Error;
use crate::domain::common::error::crypto::{CryptoError, EnvelopeField};
use crate::domain::common::log::crypto::CryptoLog;
use crate::interface::config_repo::ConfigRepo;
use crate::interface::secret_store::SecretStorePort;

pub struct SecretStore {
    database: Arc<Database>,
    cipher: Option<Aes256Gcm>,
}

impl SecretStore {
    pub fn new(database: Arc<Database>) -> Self {
        let raw_key = env::var("NETGUARDIA_SECRETS_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| env::var("NETGUARDIA_DB_KEY").ok().filter(|k| !k.is_empty()));

        let cipher = raw_key.map(|key| {
            let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), key.as_bytes());
            let mut okm = [0u8; 32];
            // SAFETY: 32 bytes is a valid output length for HKDF-SHA256
            hk.expand(b"netguardia-envelope-v1", &mut okm).unwrap();
            // SAFETY: okm is exactly 32 bytes, which is the required key size for AES-256
            Aes256Gcm::new_from_slice(&okm).unwrap()
        });

        if cipher.is_some() {
            log!(CryptoLog::EnvelopeEnabled);
        } else {
            log!(CryptoLog::EnvelopeDisabled);
        }

        Self { database, cipher }
    }

    fn encrypt(&self, plaintext: &str) -> Result<String, Error> {
        match &self.cipher {
            Some(cipher) => {
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(CryptoError::EncryptionFailed)?;
                let envelope = serde_json::json!({
                    "v": 1,
                    "alg": "aes-256-gcm",
                    "nonce": B64.encode(nonce.as_slice()),
                    "ct": B64.encode(&ciphertext),
                });
                Ok(envelope.to_string())
            }
            None => {
                let envelope = serde_json::json!({
                    "v": 1,
                    "alg": "none",
                    "nonce": "",
                    "ct": B64.encode(plaintext.as_bytes()),
                });
                Ok(envelope.to_string())
            }
        }
    }

    fn decrypt(&self, envelope_json: &str) -> Result<String, Error> {
        let env: serde_json::Value = serde_json::from_str(envelope_json).map_err(CryptoError::EnvelopeParseFailed)?;

        let version = env.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
        if version != 1 {
            Err(CryptoError::UnsupportedEnvelopeVersion(version))?;
        }

        let alg = env.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let ct_b64 = env
            .get("ct")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CryptoError::MissingEnvelopeField(EnvelopeField::Ciphertext))?;

        match alg {
            "none" => {
                if self.cipher.is_some() {
                    Err(CryptoError::AlgNoneRejected)?;
                }
                let plaintext_bytes = B64.decode(ct_b64).map_err(CryptoError::DecryptionFailed)?;
                Ok(String::from_utf8(plaintext_bytes).map_err(CryptoError::DecryptionFailed)?)
            }
            "aes-256-gcm" => {
                let cipher = self.cipher.as_ref().ok_or(CryptoError::MasterKeyUnavailable)?;

                let nonce_b64 = env
                    .get("nonce")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CryptoError::MissingEnvelopeField(EnvelopeField::Nonce))?;

                let nonce_bytes = B64.decode(nonce_b64).map_err(CryptoError::DecryptionFailed)?;
                let nonce = Nonce::from_exact_iter(nonce_bytes).ok_or(CryptoError::InvalidNonceLength)?;

                let ciphertext = B64.decode(ct_b64).map_err(CryptoError::DecryptionFailed)?;

                let plaintext_bytes = cipher
                    .decrypt(&nonce, ciphertext.as_ref())
                    .map_err(CryptoError::DecryptionFailed)?;

                Ok(String::from_utf8(plaintext_bytes).map_err(CryptoError::DecryptionFailed)?)
            }
            other => Err(CryptoError::UnsupportedAlgorithm(other))?,
        }
    }
}

#[async_trait::async_trait]
impl SecretStorePort for SecretStore {
    async fn get_secret(&self, key: &str) -> Result<Option<String>, Error> {
        let repo: &dyn ConfigRepo = self.database.as_ref();
        match repo.get_app_secret(key).await? {
            Some(envelope_json) => Ok(Some(self.decrypt(&envelope_json)?)),
            None => Ok(None),
        }
    }

    async fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        let envelope = self.encrypt(plaintext)?;
        let repo: &dyn ConfigRepo = self.database.as_ref();
        repo.set_app_secret(key, &envelope).await
    }

    fn encrypt_envelope(&self, plaintext: &str) -> Result<String, Error> {
        self.encrypt(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store_with_cipher() -> SecretStore {
        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), b"test-key-for-unit-tests");
        let mut okm = [0u8; 32];
        hk.expand(b"netguardia-envelope-v1", &mut okm).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&okm).unwrap();
        SecretStore {
            database: Arc::new(Database::new(":memory:").await.unwrap()),
            cipher: Some(cipher),
        }
    }

    async fn store_without_cipher() -> SecretStore {
        SecretStore {
            database: Arc::new(Database::new(":memory:").await.unwrap()),
            cipher: None,
        }
    }

    #[tokio::test]
    async fn encrypt_decrypt_round_trip() {
        let store = store_with_cipher().await;
        let original = "my-smtp-password-123!@#";
        let encrypted = store.encrypt(original).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[tokio::test]
    async fn encrypt_produces_different_ciphertext_each_time() {
        let store = store_with_cipher().await;
        let plaintext = "same-value";
        let e1 = store.encrypt(plaintext).unwrap();
        let e2 = store.encrypt(plaintext).unwrap();
        assert_ne!(e1, e2, "Different nonces should produce different ciphertext");
        assert_eq!(store.decrypt(&e1).unwrap(), plaintext);
        assert_eq!(store.decrypt(&e2).unwrap(), plaintext);
    }

    #[tokio::test]
    async fn wrong_key_fails_decrypt() {
        let store1 = store_with_cipher().await;
        let encrypted = store1.encrypt("secret-value").unwrap();

        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), b"different-key");
        let mut okm = [0u8; 32];
        hk.expand(b"netguardia-envelope-v1", &mut okm).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&okm).unwrap();
        let store2 = SecretStore {
            database: Arc::new(Database::new(":memory:").await.unwrap()),
            cipher: Some(cipher),
        };

        let result = store2.decrypt(&encrypted);
        assert!(result.is_err(), "Decrypting with wrong key should fail");
    }

    #[tokio::test]
    async fn alg_none_rejected_in_production_mode() {
        let store = store_with_cipher().await;
        let fake_envelope = serde_json::json!({
            "v": 1,
            "alg": "none",
            "nonce": "",
            "ct": B64.encode(b"attacker-controlled-jwt-secret"),
        })
        .to_string();
        let result = store.decrypt(&fake_envelope);
        assert!(result.is_err(), "alg:none should be rejected when cipher is present");
    }

    #[tokio::test]
    async fn alg_none_allowed_in_dev_mode() {
        let store = store_without_cipher().await;
        let encrypted = store.encrypt("dev-mode-secret").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "dev-mode-secret");
    }

    #[tokio::test]
    async fn invalid_envelope_json_fails() {
        let store = store_with_cipher().await;
        assert!(store.decrypt("not-json").is_err());
    }

    #[tokio::test]
    async fn unsupported_version_fails() {
        let store = store_with_cipher().await;
        let envelope = serde_json::json!({"v": 99, "alg": "aes-256-gcm", "ct": "abc"}).to_string();
        assert!(store.decrypt(&envelope).is_err());
    }

    #[tokio::test]
    async fn unsupported_algorithm_fails() {
        let store = store_with_cipher().await;
        let envelope = serde_json::json!({"v": 1, "alg": "chacha20", "ct": "abc"}).to_string();
        assert!(store.decrypt(&envelope).is_err());
    }
}
