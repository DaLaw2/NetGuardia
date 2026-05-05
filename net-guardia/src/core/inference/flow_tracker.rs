use std::sync::Arc;

use common::define::tcp_flags::*;
use moka::sync::Cache;
use parking_lot::Mutex;

use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::user_packet::UserPacket;
use crate::domain::detection::flow_tracker::{FlowData, FlowLimits};
use crate::domain::detection::ml_detection::FlowKey;

/// Per-flow handle: an `Arc` so map operations stay copy-cheap, with an inner
/// `Mutex` because `add_packet` is a read-modify-write that needs exclusive
/// access. Same-flow packets land on the same XSK queue (symmetric eBPF
/// hash), so this mutex is effectively single-writer; the inference tick
/// briefly contends only when it clones the entry for a snapshot.
type FlowEntry = Arc<Mutex<FlowData>>;

/// Per-queue flow tracker backed by a sharded W-TinyLFU cache (`moka`).
///
/// The hot path (`process_packet`) acquires only the per-shard moka lock
/// and the per-flow entry mutex — never a global tracker lock — so the
/// inference loop's snapshot pass (`get_uninferred_flows`,
/// `cleanup_stale_flows`) can run in parallel without stalling AF_XDP rx.
/// W-TinyLFU's frequency sketch keeps high-rate attack flows resident
/// even when burst noise floods the cache, which a strict-LRU eviction
/// policy would mishandle.
pub struct FlowTracker {
    active: Cache<FlowKey, FlowEntry>,
    limits: FlowLimits,
}

impl FlowTracker {
    pub fn new(max_flows: usize, limits: FlowLimits) -> Self {
        let cap = max_flows.max(1) as u64;
        Self {
            active: Cache::builder().max_capacity(cap).build(),
            limits,
        }
    }

    pub fn process_packet(&self, mut packet: UserPacket, is_ingress: bool) {
        let packet_key = FlowKey::from_packet(&packet);
        let reversed_key = packet_key.reverse();

        let (actual_key, is_forward) = if self.active.contains_key(&packet_key) {
            (packet_key, true)
        } else if self.active.contains_key(&reversed_key) {
            (reversed_key, false)
        } else {
            let syn = packet.tcp_flags & TCP_SYN != 0;
            let ack = packet.tcp_flags & TCP_ACK != 0;
            if syn && ack {
                if is_ingress {
                    (reversed_key, false)
                } else {
                    (packet_key, true)
                }
            } else if syn {
                (packet_key, true)
            } else if is_ingress {
                (reversed_key, false)
            } else {
                (packet_key, true)
            }
        };

        packet.is_forward = is_forward;

        let initiator_direction = if is_forward {
            if is_ingress {
                Direction::Ingress
            } else {
                Direction::Egress
            }
        } else if is_ingress {
            Direction::Egress
        } else {
            Direction::Ingress
        };

        let key_for_init = actual_key;
        let entry = self.active.get_with(actual_key, || {
            Arc::new(Mutex::new(FlowData::new(key_for_init, &packet, initiator_direction)))
        });
        entry.lock().add_packet(&packet, &self.limits);
    }

    pub fn get_flow_stats<T>(&self, convert: impl Fn(&FlowData) -> T) -> Vec<T> {
        self.active.iter().map(|(_, entry)| convert(&entry.lock())).collect()
    }

    pub fn get_uninferred_flows(&self, limit: usize) -> Vec<FlowData> {
        let mut result = Vec::new();
        for (_, entry) in self.active.iter() {
            if result.len() >= limit {
                break;
            }
            let mut flow = entry.lock();
            if flow.last_time_us > flow.last_inferred_us {
                let snapshot = FlowData {
                    fwd_packets: std::mem::take(&mut flow.fwd_packets),
                    bwd_packets: std::mem::take(&mut flow.bwd_packets),
                    active_periods: std::mem::take(&mut flow.active_periods),
                    idle_periods: std::mem::take(&mut flow.idle_periods),
                    ..flow.clone()
                };
                flow.last_inferred_us = flow.last_time_us;
                result.push(snapshot);
            }
        }
        result
    }

    pub fn flow_count(&self) -> usize {
        self.active.entry_count() as usize
    }

    pub fn cleanup_stale_flows(&self, now_us: u64) -> usize {
        let mut keys_to_remove = Vec::new();
        for (key, entry) in self.active.iter() {
            let flow = entry.lock();
            let idle = now_us.saturating_sub(flow.last_time_us);
            let is_terminated = flow.fin_count > 0 || flow.rst_count > 0;
            let stale = if is_terminated {
                idle >= self.limits.terminated_timeout_us
            } else {
                idle >= self.limits.idle_timeout_us
            };
            if stale {
                keys_to_remove.push(*key);
            }
        }
        let mut removed = 0;
        for key in keys_to_remove {
            self.active.invalidate(&key);
            removed += 1;
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits() -> FlowLimits {
        FlowLimits {
            max_packets_per_direction: 1000,
            max_periods: 1000,
            idle_threshold_us: 1_000_000,
            bulk_min_packets: 4,
            bulk_min_bytes: 1000,
            idle_timeout_us: 120_000_000,
            terminated_timeout_us: 5_000_000,
        }
    }

    fn make_packet(timestamp_us: u64, tcp_flags: u8) -> UserPacket {
        UserPacket {
            ip_version: 4,
            protocol: 6,
            tcp_flags,
            src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            packet_length: 100,
            payload_length: 60,
            header_length: 40,
            tcp_window_size: 65535,
            timestamp_us,
            is_forward: true,
        }
    }

    fn sync_count(tracker: &FlowTracker) -> usize {
        tracker.active.run_pending_tasks();
        tracker.flow_count()
    }

    #[test]
    fn cleanup_removes_idle_flows() {
        let tracker = FlowTracker::new(10000, test_limits());
        let base_ts = 1_000_000_000u64;

        let pkt = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt, false);
        assert_eq!(sync_count(&tracker), 1);

        let now = base_ts + 130_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 1);
        assert_eq!(sync_count(&tracker), 0);
    }

    #[test]
    fn cleanup_keeps_active_flows() {
        let tracker = FlowTracker::new(10000, test_limits());
        let base_ts = 1_000_000_000u64;

        let pkt = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt, false);

        let now = base_ts + 10_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 0);
        assert_eq!(sync_count(&tracker), 1);
    }

    #[test]
    fn cleanup_removes_terminated_flows_after_short_idle() {
        let tracker = FlowTracker::new(10000, test_limits());
        let base_ts = 1_000_000_000u64;

        let pkt1 = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt1, false);

        let pkt2 = make_packet(base_ts + 1_000_000, 0x01);
        tracker.process_packet(pkt2, false);

        let now = base_ts + 7_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 1);
        assert_eq!(sync_count(&tracker), 0);
    }

    #[test]
    fn cleanup_keeps_recently_terminated_flows() {
        let tracker = FlowTracker::new(10000, test_limits());
        let base_ts = 1_000_000_000u64;

        let pkt1 = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt1, false);

        let pkt2 = make_packet(base_ts + 1_000_000, 0x01);
        tracker.process_packet(pkt2, false);

        let now = base_ts + 3_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 0);
        assert_eq!(sync_count(&tracker), 1);
    }
}
