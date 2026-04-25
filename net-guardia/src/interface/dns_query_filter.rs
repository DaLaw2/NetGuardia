/// Data-plane DNS query filter — checks raw UDP-payload bytes against a
/// blacklist. Used by `XskManager` on the fast path to drop malicious DNS
/// queries before they reach the forwarding stage.
///
/// Keeping this port byte-oriented (instead of exposing parsed wire names)
/// means the implementation owns the parse + lookup together, which matters
/// for hot-path performance.
pub trait DnsQueryFilter: Send + Sync {
    /// Returns `true` when `raw` is a DNS query whose QNAME is on the
    /// blacklist. Returns `false` for non-DNS traffic and for clean DNS.
    fn is_query_blacklisted(&self, raw: &[u8]) -> bool;
}
