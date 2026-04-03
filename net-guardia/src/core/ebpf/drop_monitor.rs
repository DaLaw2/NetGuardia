use std::mem;
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use tokio::sync::{broadcast, oneshot};

use common::define::drop_reason::*;
use common::model::drop_event::DropEvent as RawDropEvent;
use parking_lot::Mutex;

use crate::model::config::constants::DROP_CHANNEL_CAPACITY;
use crate::model::drop_event::{DropCounters, DropEventMessage};

pub struct DropMonitor {
    broadcast_tx: broadcast::Sender<DropEventMessage>,
    counters: Mutex<DropCounters>,
}

impl DropMonitor {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(DROP_CHANNEL_CAPACITY);
        Self {
            broadcast_tx: tx,
            counters: Mutex::new(DropCounters::default()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DropEventMessage> {
        self.broadcast_tx.subscribe()
    }

    pub fn get_counters(&self) -> DropCounters {
        self.counters.lock().clone()
    }

    fn process_event(&self, raw: &RawDropEvent) {
        // Update counters
        {
            let mut c = self.counters.lock();
            c.total += 1;
            match raw.reason {
                DROP_REASON_ACL_BLACKLIST => c.acl_blacklist += 1,
                DROP_REASON_RATE_LIMIT_PKT => c.rate_limit_pkt += 1,
                DROP_REASON_RATE_LIMIT_SYN => c.rate_limit_syn += 1,
                DROP_REASON_RATE_LIMIT_UDP => c.rate_limit_udp += 1,
                DROP_REASON_RATE_LIMIT_DNS => c.rate_limit_dns += 1,
                DROP_REASON_PROTOCOL_FILTER => c.protocol_filter += 1,
                DROP_REASON_DNS_BLACKLIST => c.dns_blacklist += 1,
                DROP_REASON_GEO_BLOCK => c.geo_block += 1,
                _ => {}
            }
        }

        let reason_str = reason_to_str(raw.reason);

        // Format IPs based on version
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

impl Default for DropMonitor {
    fn default() -> Self {
        Self::new()
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
            // IPv6 - format as hex
            let src = format_ipv6(&raw.src_ip);
            let dst = format_ipv6(&raw.dst_ip);
            (src, dst)
        }
    }
}

fn format_ipv6(bytes: &[u8; 16]) -> String {
    std::net::Ipv6Addr::from(*bytes).to_string()
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

/// Start the ring buffer consumer as a tokio task. Returns a shutdown sender.
pub async fn start_consumer(ring_buf: RingBuf<MapData>, monitor: Arc<DropMonitor>) -> oneshot::Sender<()> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

    tokio::spawn(async move {
        let mut ring_buf = ring_buf;
        let mut interval = tokio::time::interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {}
            }

            while let Some(item) = ring_buf.next() {
                if item.len() >= mem::size_of::<RawDropEvent>() {
                    let event = unsafe { &*(item.as_ptr() as *const RawDropEvent) };
                    monitor.process_event(event);
                }
            }
        }
    });

    shutdown_tx
}
