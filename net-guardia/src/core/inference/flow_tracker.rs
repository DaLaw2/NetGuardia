use std::sync::Arc;

use moka::sync::Cache;
use net_guardia_abi::define::tcp_flags::*;
use parking_lot::Mutex;

use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::user_packet::UserPacket;
use crate::domain::detection::flow_tracker::{FlowData, FlowLimits, FlowSnapshot};
use crate::domain::detection::ml_detection::FlowKey;

struct TrackedFlow {
    data: FlowData,
    last_inferred_us: u64,
}

type FlowEntry = Arc<Mutex<TrackedFlow>>;

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

        if let Some(entry) = self.active.get(&packet_key) {
            packet.is_forward = true;
            entry.lock().data.add_packet(&packet, &self.limits);
            return;
        }

        let reversed_key = packet_key.reverse();
        if let Some(entry) = self.active.get(&reversed_key) {
            packet.is_forward = false;
            entry.lock().data.add_packet(&packet, &self.limits);
            return;
        }

        let syn = packet.tcp_flags & TCP_SYN != 0;
        let ack = packet.tcp_flags & TCP_ACK != 0;
        let (actual_key, is_forward) = if syn && ack {
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
            Arc::new(Mutex::new(TrackedFlow {
                data: FlowData::new(key_for_init, &packet, initiator_direction),
                last_inferred_us: 0,
            }))
        });
        entry.lock().data.add_packet(&packet, &self.limits);
    }

    pub fn get_flow_stats<T>(&self, convert: impl Fn(&FlowData) -> T) -> Vec<T> {
        self.active
            .iter()
            .map(|(_, entry)| convert(&entry.lock().data))
            .collect()
    }

    pub fn get_filtered_flow_stats<T>(
        &self,
        filter: impl Fn(&FlowData) -> bool,
        convert: impl Fn(&FlowData) -> T,
    ) -> Vec<T> {
        self.active
            .iter()
            .filter_map(|(_, entry)| {
                let tracked = entry.lock();
                filter(&tracked.data).then(|| convert(&tracked.data))
            })
            .collect()
    }

    pub fn get_uninferred_flows(&self, limit: usize) -> Vec<FlowSnapshot> {
        let mut clones = Vec::new();
        for (_, entry) in self.active.iter() {
            if clones.len() >= limit {
                break;
            }
            let mut tracked = entry.lock();
            if tracked.data.last_time_us > tracked.last_inferred_us {
                clones.push(tracked.data.clone());
                tracked.last_inferred_us = tracked.data.last_time_us;
            }
        }
        clones.iter().map(FlowSnapshot::from_flow_data).collect()
    }

    pub fn flow_count(&self) -> usize {
        self.active.entry_count() as usize
    }

    pub fn summary_stats(&self) -> (usize, u64, usize) {
        let mut total_flows = 0usize;
        let mut total_bytes = 0u64;
        let mut total_packets = 0usize;

        for (_, entry) in self.active.iter() {
            let flow = entry.lock();
            total_flows += 1;
            total_bytes += flow.data.fwd_total_bytes + flow.data.bwd_total_bytes;
            total_packets += flow.data.packet_count();
        }

        (total_flows, total_bytes, total_packets)
    }

    pub fn cleanup_stale_flows(&self, now_us: u64) -> usize {
        let mut keys_to_remove = Vec::new();
        for (key, entry) in self.active.iter() {
            let flow = entry.lock();
            let idle = now_us.saturating_sub(flow.data.last_time_us);
            let is_terminated = flow.data.fin_count > 0 || flow.data.rst_count > 0;
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
    use crate::domain::data_plane::direction::Direction;
    use crate::domain::data_plane::ip_version::IpVersion;

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
            ip_version: IpVersion::V4,
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
    fn reverse_packet_updates_existing_flow_backward_side() {
        let tracker = FlowTracker::new(10000, test_limits());
        let first = make_packet(1_000_000, TCP_SYN);
        let mut reply = make_packet(1_001_000, TCP_ACK);
        (reply.src_ip, reply.dst_ip) = (reply.dst_ip, reply.src_ip);
        (reply.src_port, reply.dst_port) = (reply.dst_port, reply.src_port);

        tracker.process_packet(first, false);
        tracker.process_packet(reply, true);

        let flows = tracker.get_flow_stats(|flow| {
            (
                flow.direction,
                flow.fwd_packets.len(),
                flow.bwd_packets.len(),
                flow.fwd_total_bytes + flow.bwd_total_bytes,
                flow.flow_key.src_port,
                flow.flow_key.dst_port,
            )
        });
        assert_eq!(flows, vec![(Direction::Egress, 1, 1, 200, 12345, 80)]);
        assert_eq!(tracker.summary_stats(), (1, 200, 2));
    }

    #[test]
    fn uninferred_snapshots_do_not_drain_packet_history() {
        let tracker = FlowTracker::new(10000, test_limits());

        tracker.process_packet(make_packet(1_000_000, TCP_SYN), false);
        tracker.process_packet(make_packet(1_001_000, TCP_ACK), false);

        let first_snapshot = tracker.get_uninferred_flows(10);
        assert_eq!(first_snapshot[0].packet_count, 2);

        tracker.process_packet(make_packet(1_002_000, TCP_ACK), false);
        tracker.process_packet(make_packet(1_003_000, TCP_ACK), false);
        tracker.process_packet(make_packet(1_004_000, TCP_ACK), false);

        let second_snapshot = tracker.get_uninferred_flows(10);
        assert_eq!(second_snapshot[0].packet_count, 5);
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
