use std::mem::size_of;
use std::net::Ipv6Addr;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use macros::log;
use net_guardia_abi::define::drop_reason::*;
use net_guardia_abi::model::drop_event::DropEvent as RawDropEvent;
use tokio::sync::{broadcast, oneshot};
use tokio::time::interval;

use crate::domain::data_plane::drop_event::{DropCounters, DropEventMessage};
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::log::EbpfLog;
use crate::interface::data_plane::drop_stats::DropStatsPort;

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
}

impl DropCountersAtomic {
    pub fn snapshot(&self) -> DropCounters {
        let acl_blacklist = self.acl_blacklist.load(Ordering::Relaxed);
        let rate_limit_pkt = self.rate_limit_pkt.load(Ordering::Relaxed);
        let rate_limit_syn = self.rate_limit_syn.load(Ordering::Relaxed);
        let rate_limit_udp = self.rate_limit_udp.load(Ordering::Relaxed);
        let rate_limit_dns = self.rate_limit_dns.load(Ordering::Relaxed);
        let protocol_filter = self.protocol_filter.load(Ordering::Relaxed);
        let dns_blacklist = self.dns_blacklist.load(Ordering::Relaxed);
        let geo_block = self.geo_block.load(Ordering::Relaxed);
        let total = acl_blacklist
            + rate_limit_pkt
            + rate_limit_syn
            + rate_limit_udp
            + rate_limit_dns
            + protocol_filter
            + dns_blacklist
            + geo_block;
        DropCounters {
            acl_blacklist,
            rate_limit_pkt,
            rate_limit_syn,
            rate_limit_udp,
            rate_limit_dns,
            protocol_filter,
            dns_blacklist,
            geo_block,
            total,
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

    pub fn record_drop_count(&self, reason: u8) {
        if let Some(counter) = self.bucket_for(reason) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_drop_event(&self, raw: &RawDropEvent) {
        self.record_drop_count(raw.reason);
        let Some(ip_version) = IpVersion::from_u8(raw.ip_version) else {
            return;
        };
        if self.broadcast_tx.receiver_count() == 0 {
            return;
        }

        let reason_str = reason_to_str(raw.reason);

        let (src_ip, dst_ip) = format_ips(raw, ip_version);

        let msg = DropEventMessage {
            timestamp_ns: raw.timestamp_ns,
            src_ip,
            dst_ip,
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            protocol: raw.protocol,
            reason: reason_str.to_string(),
            ip_version,
        };

        if let Err(err) = self.broadcast_tx.send(msg) {
            log!(EbpfLog::DropBroadcastFailed(err.to_string()));
        }
    }
}

impl DropStatsPort for DropMonitor {
    fn get_counters(&self) -> DropCounters {
        self.counters.snapshot()
    }
}

fn format_ips(raw: &RawDropEvent, ip_version: IpVersion) -> (String, String) {
    match ip_version {
        IpVersion::V4 => {
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
        IpVersion::V6 => {
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
        let mut interval = interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {}
            }

            while let Some(item) = ring_buf.next() {
                if let Some(event) = raw_drop_event_from_bytes(&item) {
                    monitor.record_drop_event(&event);
                }
            }
        }
    });

    shutdown_tx
}

fn raw_drop_event_from_bytes(bytes: &[u8]) -> Option<RawDropEvent> {
    if bytes.len() < size_of::<RawDropEvent>() {
        return None;
    }

    // SAFETY: The length check guarantees enough initialized bytes for RawDropEvent.
    let event = unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawDropEvent>()) };
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_drop_event() -> RawDropEvent {
        RawDropEvent {
            timestamp_ns: 42,
            src_ip: [1; 16],
            dst_ip: [2; 16],
            src_port: 1234,
            dst_port: 443,
            protocol: 6,
            reason: DROP_REASON_ACL_BLACKLIST,
            ip_version: IpVersion::V4 as u8,
            _pad: 0,
        }
    }

    fn event_bytes(event: &RawDropEvent) -> Vec<u8> {
        // SAFETY: RawDropEvent is a repr(C), Copy ABI record borrowed as bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts((event as *const RawDropEvent).cast::<u8>(), size_of::<RawDropEvent>())
        };
        bytes.to_vec()
    }

    #[test]
    fn raw_drop_event_from_bytes_rejects_short_buffers() {
        let bytes = vec![0; size_of::<RawDropEvent>() - 1];

        assert!(raw_drop_event_from_bytes(&bytes).is_none());
    }

    #[test]
    fn raw_drop_event_from_bytes_accepts_unaligned_buffers() {
        let event = sample_drop_event();
        let mut bytes = vec![0];
        bytes.extend(event_bytes(&event));

        let parsed = raw_drop_event_from_bytes(&bytes[1..]).expect("drop event");

        assert_eq!(parsed.timestamp_ns, event.timestamp_ns);
        assert_eq!(parsed.src_port, event.src_port);
        assert_eq!(parsed.reason, event.reason);
    }
}
