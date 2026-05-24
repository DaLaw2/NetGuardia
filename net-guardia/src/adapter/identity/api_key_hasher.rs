use std::fmt::Write;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::interface::identity::api_key_hasher::ApiKeyHasher;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacApiKeyHasher {
    key: [u8; 32],
}

impl HmacApiKeyHasher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl ApiKeyHasher for HmacApiKeyHasher {
    fn hash_api_key(&self, raw_key: &str) -> String {
        let mut mac = match HmacSha256::new_from_slice(&self.key) {
            Ok(mac) => mac,
            // SAFETY: HMAC accepts keys of any length; `key` is a fixed 32-byte array.
            Err(_) => unreachable!("HMAC-SHA256 accepts fixed 32-byte keys"),
        };
        mac.update(raw_key.as_bytes());
        let result = mac.finalize().into_bytes();

        let mut hex = String::with_capacity(64);
        for byte in result {
            // SAFETY: write! on a String is infallible.
            let _ = write!(&mut hex, "{:02x}", byte);
        }
        hex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hash() {
        let hasher = HmacApiKeyHasher::new([0xAB; 32]);
        let h1 = hasher.hash_api_key("test-key");
        let h2 = hasher.hash_api_key("test-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn different_keys_produce_different_hashes() {
        let hasher = HmacApiKeyHasher::new([0xAB; 32]);
        let h1 = hasher.hash_api_key("key-a");
        let h2 = hasher.hash_api_key("key-b");
        assert_ne!(h1, h2);
    }
}
