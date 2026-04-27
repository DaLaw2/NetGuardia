use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use common::define::drop_reason::*;
use common::model::drop_event::DropEvent as RawDropEvent;
use tokio::sync::{broadcast, oneshot};
use tokio::time::interval;

use crate::domain::data_plane::drop_event::{DropCounters, DropEventMessage};
use crate::interface::drop_stats::DropStatsPort;

#[derive(Default)]
pub struct DropCountersAtomic {
    acl_blacklist: AtomicU64,
    rate_limit_pkt: AtomicU64,
    rate_limit_syn: AtomicU64,
    rate_limit_udp: AtomicU64,
    rate_limit_dns: AtomicU64,
    protocol_filter: AtomicU64,
    dns_blacklist: AtomicU64,
    geo_block: AtomicU64,
    total: AtomicU64,
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

pub struct DropMonitor {
    broadcast_tx: broadcast::Sender<DropEventMessage>,
    counters: DropCountersAtomic,
}

impl DropMonitor {
    pub fn new(channel_capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(channel_capacity.max(1));
        Self {
            broadcast_tx: tx,
            counters: DropCountersAtomic::default(),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DropEventMessage> {
        self.broadcast_tx.subscribe()
    }

    fn bucket_for(&self, reason: u8) -> Option<&AtomicU64> {
        match reason {
            DROP_REASON_ACL_BLACKLIST => Some(&self.counters.acl_blacklist),
            DROP_REASON_RATE_LIMIT_PKT => Some(&self.counters.rate_limit_pkt),
            DROP_REASON_RATE_LIMIT_SYN => Some(&self.counters.rate_limit_syn),
            DROP_REASON_RATE_LIMIT_UDP => Some(&self.counters.rate_limit_udp),
            DROP_REASON_RATE_LIMIT_DNS => Some(&self.counters.rate_limit_dns),
            DROP_REASON_PROTOCOL_FILTER => Some(&self.counters.protocol_filter),
            DROP_REASON_DNS_BLACKLIST => Some(&self.counters.dns_blacklist),
            DROP_REASON_GEO_BLOCK => Some(&self.counters.geo_block),
            _ => None,
        }
    }

    fn record_drop(&self, reason: u8) {
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        if let Some(counter) = self.bucket_for(reason) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_userspace_drop_count_only(&self, reason: u8) {
        self.record_drop(reason);
    }

    fn process_event(&self, raw: &RawDropEvent) {
        self.record_drop(raw.reason);

        let reason_str = reason_to_str(raw.reason);

        let (src_ip, dst_ip) = format_ips(raw);

        let msg = DropEventMessage {
            timestamp_ns: raw.timestamp_ns,
            src_ip,
            dst_ip,
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            protocol: raw.protocol,
            reason: reason_str.to_string(),
            ip_version: raw.ip_version,
        };

        let _ = self.broadcast_tx.send(msg);
    }
}

impl DropStatsPort for DropMonitor {
    fn get_counters(&self) -> DropCounters {
        self.counters.snapshot()
    }
}

fn format_ips(raw: &RawDropEvent) -> (String, String) {
    match raw.ip_version {
        4 => {
            let src = format!(
                "{}.{}.{}.{}",
                raw.src_ip[0], raw.src_ip[1], raw.src_ip[2], raw.src_ip[3]
            );
            let dst = format!(
                "{}.{}.{}.{}",
                raw.dst_ip[0], raw.dst_ip[1], raw.dst_ip[2], raw.dst_ip[3]
            );
            (src, dst)
        }
        _ => {
            let src = format_ipv6(&raw.src_ip);
            let dst = format_ipv6(&raw.dst_ip);
            (src, dst)
        }
    }
}

fn format_ipv6(bytes: &[u8; 16]) -> String {
    Ipv6Addr::from(*bytes).to_string()
}

fn reason_to_str(reason: u8) -> &'static str {
    match reason {
        DROP_REASON_ACL_BLACKLIST => "acl_blacklist",
        DROP_REASON_RATE_LIMIT_PKT => "rate_limit_packet",
        DROP_REASON_RATE_LIMIT_SYN => "rate_limit_syn",
        DROP_REASON_RATE_LIMIT_UDP => "rate_limit_udp",
        DROP_REASON_RATE_LIMIT_DNS => "rate_limit_dns",
        DROP_REASON_PROTOCOL_FILTER => "protocol_filter",
        DROP_REASON_DNS_BLACKLIST => "dns_blacklist",
        DROP_REASON_GEO_BLOCK => "geo_block",
        _ => "unknown",
    }
}

pub async fn start_consumer(ring_buf: RingBuf<MapData>, monitor: Arc<DropMonitor>) -> oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut ring_buf = ring_buf;
        // todo add interval value to config
        let mut interval = interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {}
            }

            while let Some(item) = ring_buf.next() {
                if item.len() >= size_of::<RawDropEvent>() {
                    let event = unsafe { &*(item.as_ptr() as *const RawDropEvent) };
                    monitor.process_event(event);
                }
            }
        }
    });

    shutdown_tx
}
