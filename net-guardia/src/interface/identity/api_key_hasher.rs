pub trait ApiKeyHasher: Send + Sync {
    fn hash_api_key(&self, raw_key: &str) -> String;
}
