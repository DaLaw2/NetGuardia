use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DropEventMessage {
    pub timestamp_ns: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub reason: String,
    pub ip_version: u8,
}

/// Wire snapshot of drop counts. Returned by `DropMonitor::snapshot` and
/// serialized to JSON for the HTTP stats endpoint.
#[derive(Default, Clone, Serialize)]
pub struct DropCounters {
    pub acl_blacklist: u64,
    pub rate_limit_pkt: u64,
    pub rate_limit_syn: u64,
    pub rate_limit_udp: u64,
    pub rate_limit_dns: u64,
    pub protocol_filter: u64,
    pub dns_blacklist: u64,
    pub geo_block: u64,
    pub total: u64,
}

/// Lock-free atomic counters incremented on the drop ring-buffer consumer
/// path. `Relaxed` is sufficient — counters are independent and the
/// snapshot does not require a global consistent ordering across them.
#[derive(Default)]
pub struct DropCountersAtomic {
    pub acl_blacklist: AtomicU64,
    pub rate_limit_pkt: AtomicU64,
    pub rate_limit_syn: AtomicU64,
    pub rate_limit_udp: AtomicU64,
    pub rate_limit_dns: AtomicU64,
    pub protocol_filter: AtomicU64,
    pub dns_blacklist: AtomicU64,
    pub geo_block: AtomicU64,
    pub total: AtomicU64,
}

impl DropCountersAtomic {
    pub fn snapshot(&self) -> DropCounters {
        DropCounters {
            acl_blacklist: self.acl_blacklist.load(Ordering::Relaxed),
            rate_limit_pkt: self.rate_limit_pkt.load(Ordering::Relaxed),
            rate_limit_syn: self.rate_limit_syn.load(Ordering::Relaxed),
            rate_limit_udp: self.rate_limit_udp.load(Ordering::Relaxed),
            rate_limit_dns: self.rate_limit_dns.load(Ordering::Relaxed),
            protocol_filter: self.protocol_filter.load(Ordering::Relaxed),
            dns_blacklist: self.dns_blacklist.load(Ordering::Relaxed),
            geo_block: self.geo_block.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
        }
    }
}
