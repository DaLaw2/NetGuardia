pub trait DnsQueryFilter: Send + Sync {
    fn is_query_blacklisted(&self, raw: &[u8]) -> bool;
}
