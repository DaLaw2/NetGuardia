use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use sha2::Sha256;

use macros::log;

use crate::adapter::persistence::Database;
use crate::interface::port::secret_store::SecretStorePort;
use crate::model::error::Error;
use crate::model::error::crypto::CryptoError;
use crate::model::log::crypto::CryptoLog;

/// AES-256-GCM envelope encryption for sensitive values stored in `app_secrets`.
pub struct SecretStore {
    db: Arc<Database>,
    /// `None` means dev mode — secrets are base64-encoded but not encrypted.
    cipher: Option<Aes256Gcm>,
}

impl SecretStore {
    pub fn new(db: Arc<Database>) -> Self {
        let raw_key = std::env::var("NETGUARDIA_SECRETS_KEY")
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| std::env::var("NETGUARDIA_DB_KEY").ok().filter(|k| !k.is_empty()));

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

        Self { db, cipher }
    }

    fn encrypt(&self, plaintext: &str) -> Result<String, Error> {
        match &self.cipher {
            Some(cipher) => {
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|e| CryptoError::EncryptionFailed { reason: e.to_string() })?;
                let envelope = serde_json::json!({
                    "v": 1,
                    "alg": "aes-256-gcm",
                    "nonce": B64.encode(nonce.as_slice()),
                    "ct": B64.encode(&ciphertext),
                });
                Ok(envelope.to_string())
            }
            None => {
                // Dev mode: no encryption, just base64
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
        let env: serde_json::Value =
            serde_json::from_str(envelope_json).map_err(|e| CryptoError::InvalidEnvelope { reason: e.to_string() })?;

        let version = env.get("v").and_then(|v| v.as_u64()).unwrap_or(0);
        if version != 1 {
            return Err(CryptoError::InvalidEnvelope {
                reason: format!("unsupported envelope version: {version}"),
            }
            .into());
        }

        let alg = env.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let ct_b64 = env
            .get("ct")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CryptoError::InvalidEnvelope {
                reason: "missing ct field".to_string(),
            })?;

        match alg {
            "none" => {
                // Reject alg:none when encryption is enabled (production mode).
                // Prevents downgrade attack where attacker replaces encrypted envelope
                // with alg:none + attacker-controlled plaintext.
                if self.cipher.is_some() {
                    return Err(CryptoError::InvalidEnvelope {
                        reason: "alg:none rejected in production mode (encryption key is set)".to_string(),
                    }
                    .into());
                }
                let plaintext_bytes = B64
                    .decode(ct_b64)
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() })?;
                String::from_utf8(plaintext_bytes)
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() }.into())
            }
            "aes-256-gcm" => {
                let cipher = self.cipher.as_ref().ok_or(CryptoError::MasterKeyUnavailable)?;

                let nonce_b64 =
                    env.get("nonce")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| CryptoError::InvalidEnvelope {
                            reason: "missing nonce field".to_string(),
                        })?;

                let nonce_bytes = B64
                    .decode(nonce_b64)
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() })?;
                let nonce =
                    Nonce::from_exact_iter(nonce_bytes.into_iter()).ok_or_else(|| CryptoError::DecryptionFailed {
                        reason: "invalid nonce length".to_string(),
                    })?;

                let ciphertext = B64
                    .decode(ct_b64)
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() })?;

                let plaintext_bytes = cipher
                    .decrypt(&nonce, ciphertext.as_ref())
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() })?;

                String::from_utf8(plaintext_bytes)
                    .map_err(|e| CryptoError::DecryptionFailed { reason: e.to_string() }.into())
            }
            other => Err(CryptoError::InvalidEnvelope {
                reason: format!("unsupported algorithm: {other}"),
            }
            .into()),
        }
    }

    /// Idempotent startup migration: moves plaintext secrets from settings/notification_config
    /// into the encrypted `app_secrets` table.
    pub fn migrate_plaintext_secrets(&self) -> Result<(), Error> {
        // Check if migration already done
        if let Some(v) = self.db.get_setting("secrets_migrated")?
            && v == "true"
        {
            log!(CryptoLog::MigrationSkipped);
            return Ok(());
        }

        let mut count = 0usize;

        // 1. Migrate smtp_password
        if let Some(password) = self.db.get_setting("smtp_password")?
            && password != "__encrypted__"
            && !password.is_empty()
        {
            self.set_secret("smtp_password", &password)?;
            self.db.set_setting("smtp_password", "__encrypted__")?;
            log!(CryptoLog::SecretMigrated("smtp_password".to_string()));
            count += 1;
        }

        // 2. Migrate telegram_bot_token from notification_config JSON
        if let Some(json_str) = self.db.get_notification_config("telegram")?
            && let Ok(mut config) = serde_json::from_str::<serde_json::Value>(&json_str)
            && let Some(token) = config.get("bot_token").and_then(|v| v.as_str()).map(|s| s.to_string())
            && token != "__encrypted__"
            && !token.is_empty()
        {
            self.set_secret("telegram_bot_token", &token)?;
            config["bot_token"] = serde_json::Value::String("__encrypted__".to_string());
            self.db.set_notification_config("telegram", &config.to_string())?;
            log!(CryptoLog::SecretMigrated("telegram_bot_token".to_string()));
            count += 1;
        }

        // 3. Migrate jwt_secret
        if let Some(secret) = self.db.get_setting("jwt_secret")?
            && secret != "__encrypted__"
            && !secret.is_empty()
        {
            self.set_secret("jwt_secret", &secret)?;
            self.db.set_setting("jwt_secret", "__encrypted__")?;
            log!(CryptoLog::SecretMigrated("jwt_secret".to_string()));
            count += 1;
        }

        self.db.set_setting("secrets_migrated", "true")?;
        log!(CryptoLog::MigrationComplete(count));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a SecretStore with encryption enabled (production mode).
    fn store_with_cipher() -> SecretStore {
        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), b"test-key-for-unit-tests");
        let mut okm = [0u8; 32];
        hk.expand(b"netguardia-envelope-v1", &mut okm).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&okm).unwrap();
        SecretStore {
            db: Arc::new(Database::new(":memory:").unwrap()),
            cipher: Some(cipher),
        }
    }

    /// Create a SecretStore without encryption (dev mode).
    fn store_without_cipher() -> SecretStore {
        SecretStore {
            db: Arc::new(Database::new(":memory:").unwrap()),
            cipher: None,
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let store = store_with_cipher();
        let original = "my-smtp-password-123!@#";
        let encrypted = store.encrypt(original).unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn encrypt_produces_different_ciphertext_each_time() {
        let store = store_with_cipher();
        let plaintext = "same-value";
        let e1 = store.encrypt(plaintext).unwrap();
        let e2 = store.encrypt(plaintext).unwrap();
        assert_ne!(e1, e2, "Different nonces should produce different ciphertext");
        assert_eq!(store.decrypt(&e1).unwrap(), plaintext);
        assert_eq!(store.decrypt(&e2).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let store1 = store_with_cipher();
        let encrypted = store1.encrypt("secret-value").unwrap();

        // Create a store with a different key
        let hk = Hkdf::<Sha256>::new(Some(b"netguardia-v1-salt"), b"different-key");
        let mut okm = [0u8; 32];
        hk.expand(b"netguardia-envelope-v1", &mut okm).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&okm).unwrap();
        let store2 = SecretStore {
            db: Arc::new(Database::new(":memory:").unwrap()),
            cipher: Some(cipher),
        };

        let result = store2.decrypt(&encrypted);
        assert!(result.is_err(), "Decrypting with wrong key should fail");
    }

    #[test]
    fn alg_none_rejected_in_production_mode() {
        let store = store_with_cipher();
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

    #[test]
    fn alg_none_allowed_in_dev_mode() {
        let store = store_without_cipher();
        let encrypted = store.encrypt("dev-mode-secret").unwrap();
        let decrypted = store.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "dev-mode-secret");
    }

    #[test]
    fn invalid_envelope_json_fails() {
        let store = store_with_cipher();
        assert!(store.decrypt("not-json").is_err());
    }

    #[test]
    fn unsupported_version_fails() {
        let store = store_with_cipher();
        let envelope = serde_json::json!({"v": 99, "alg": "aes-256-gcm", "ct": "abc"}).to_string();
        assert!(store.decrypt(&envelope).is_err());
    }

    #[test]
    fn unsupported_algorithm_fails() {
        let store = store_with_cipher();
        let envelope = serde_json::json!({"v": 1, "alg": "chacha20", "ct": "abc"}).to_string();
        assert!(store.decrypt(&envelope).is_err());
    }
}

impl SecretStorePort for SecretStore {
    fn get_secret(&self, key: &str) -> Result<Option<String>, Error> {
        match self.db.get_app_secret(key)? {
            Some(envelope_json) => Ok(Some(self.decrypt(&envelope_json)?)),
            None => Ok(None),
        }
    }

    fn set_secret(&self, key: &str, plaintext: &str) -> Result<(), Error> {
        let envelope = self.encrypt(plaintext)?;
        self.db.set_app_secret(key, &envelope)
    }
}
