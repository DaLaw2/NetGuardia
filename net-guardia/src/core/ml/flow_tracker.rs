use std::num::NonZero;

use common::define::tcp_flags::*;
use lru::LruCache;

use crate::model::config::constants::{
    FLOW_BULK_MIN_BYTES, FLOW_BULK_MIN_PACKETS, FLOW_IDLE_THRESHOLD_US, FLOW_IDLE_TIMEOUT_US,
    FLOW_MAX_PACKETS_PER_DIRECTION, FLOW_MAX_PERIODS, FLOW_TERMINATED_TIMEOUT_US,
};
use crate::model::direction::Direction;
use crate::model::ml_detection::{BulkState, FlowKey, PacketData};
use crate::model::user_packet::UserPacket;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub flow_key: FlowKey,
    pub direction: Direction,
    pub start_time_us: u64,
    pub last_time_us: u64,
    pub fwd_packets: Vec<PacketData>,
    pub fwd_total_bytes: u64,
    pub fwd_header_bytes: u64,
    pub bwd_packets: Vec<PacketData>,
    pub bwd_total_bytes: u64,
    pub bwd_header_bytes: u64,
    pub fin_count: u32,
    pub syn_count: u32,
    pub rst_count: u32,
    pub psh_count: u32,
    pub ack_count: u32,
    pub urg_count: u32,
    pub cwe_count: u32,
    pub ece_count: u32,
    pub init_win_bytes_fwd: u16,
    pub init_win_bytes_bwd: u16,
    pub active_periods: Vec<u64>,
    pub idle_periods: Vec<u64>,
    pub last_packet_time: u64,
    pub fwd_bulk_state: BulkState,
    pub bwd_bulk_state: BulkState,
    pub act_data_pkt_fwd: u32,
    is_first_packet: bool,
    /// Timestamp (us) when this flow was last sent to ML inference.
    /// 0 means never inferred. Used to avoid re-inferring unchanged flows.
    pub last_inferred_us: u64,
}

impl FlowData {
    pub fn new(flow_key: FlowKey, first_packet: &UserPacket, direction: Direction) -> Self {
        Self {
            flow_key,
            direction,
            start_time_us: first_packet.timestamp_us,
            last_time_us: first_packet.timestamp_us,
            fwd_packets: Vec::new(),
            fwd_total_bytes: 0,
            fwd_header_bytes: 0,
            bwd_packets: Vec::new(),
            bwd_total_bytes: 0,
            bwd_header_bytes: 0,
            fin_count: 0,
            syn_count: 0,
            rst_count: 0,
            psh_count: 0,
            ack_count: 0,
            urg_count: 0,
            cwe_count: 0,
            ece_count: 0,
            init_win_bytes_fwd: if first_packet.is_forward {
                first_packet.tcp_window_size
            } else {
                0
            },
            init_win_bytes_bwd: if !first_packet.is_forward {
                first_packet.tcp_window_size
            } else {
                0
            },
            active_periods: Vec::new(),
            idle_periods: Vec::new(),
            last_packet_time: first_packet.timestamp_us,
            fwd_bulk_state: BulkState::default(),
            bwd_bulk_state: BulkState::default(),
            act_data_pkt_fwd: 0,
            is_first_packet: true,
            last_inferred_us: 0,
        }
    }

    pub fn add_packet(&mut self, packet: &UserPacket) {
        let packet_data = PacketData {
            timestamp_us: packet.timestamp_us,
            length: packet.packet_length,
            header_length: packet.header_length,
            payload_length: packet.payload_length,
            flags: packet.tcp_flags,
        };

        if packet.tcp_flags & TCP_FIN != 0 {
            self.fin_count += 1;
        }
        if packet.tcp_flags & TCP_SYN != 0 {
            self.syn_count += 1;
        }
        if packet.tcp_flags & TCP_RST != 0 {
            self.rst_count += 1;
        }
        if packet.tcp_flags & TCP_PSH != 0 {
            self.psh_count += 1;
        }
        if packet.tcp_flags & TCP_ACK != 0 {
            self.ack_count += 1;
        }
        if packet.tcp_flags & TCP_URG != 0 {
            self.urg_count += 1;
        }
        if packet.tcp_flags & TCP_CWR != 0 {
            self.cwe_count += 1;
        }
        if packet.tcp_flags & TCP_ECE != 0 {
            self.ece_count += 1;
        }

        let iat = packet.timestamp_us.saturating_sub(self.last_packet_time);

        if iat > FLOW_IDLE_THRESHOLD_US {
            if self.idle_periods.len() < FLOW_MAX_PERIODS {
                self.idle_periods.push(iat);
            }
        } else if iat > 0 && self.active_periods.len() < FLOW_MAX_PERIODS {
            self.active_periods.push(iat);
        }

        self.last_packet_time = packet.timestamp_us;
        self.last_time_us = packet.timestamp_us;

        if self.is_first_packet {
            self.is_first_packet = false;
        } else if packet.is_forward && packet.payload_length > 0 {
            self.act_data_pkt_fwd += 1;
        }

        if packet.is_forward {
            if self.fwd_packets.len() < FLOW_MAX_PACKETS_PER_DIRECTION {
                self.fwd_packets.push(packet_data.clone());
            }
            self.fwd_total_bytes += packet.payload_length as u64;
            self.fwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_fwd == 0 {
                self.init_win_bytes_fwd = packet.tcp_window_size;
            }
            Self::update_bulk_state(&mut self.fwd_bulk_state, &packet_data);
        } else {
            if self.bwd_packets.len() < FLOW_MAX_PACKETS_PER_DIRECTION {
                self.bwd_packets.push(packet_data.clone());
            }
            self.bwd_total_bytes += packet.payload_length as u64;
            self.bwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_bwd == 0 {
                self.init_win_bytes_bwd = packet.tcp_window_size;
            }
            Self::update_bulk_state(&mut self.bwd_bulk_state, &packet_data);
        }
    }

    fn update_bulk_state(bulk_state: &mut BulkState, packet: &PacketData) {
        if packet.payload_length > 0 {
            if !bulk_state.in_bulk {
                bulk_state.in_bulk = true;
                bulk_state.last_bulk_bytes = packet.length as u64;
                bulk_state.last_bulk_packets = 1;
                bulk_state.last_bulk_start_us = packet.timestamp_us;
                bulk_state.last_bulk_packet_us = packet.timestamp_us;
            } else {
                bulk_state.last_bulk_bytes += packet.length as u64;
                bulk_state.last_bulk_packets += 1;
                bulk_state.last_bulk_packet_us = packet.timestamp_us;
            }
        } else {
            if bulk_state.in_bulk
                && bulk_state.last_bulk_packets >= FLOW_BULK_MIN_PACKETS
                && bulk_state.last_bulk_bytes >= FLOW_BULK_MIN_BYTES
            {
                bulk_state.bulk_count += 1;
                bulk_state.total_bytes += bulk_state.last_bulk_bytes;
                bulk_state.total_packets += bulk_state.last_bulk_packets;
                bulk_state.total_duration_us += bulk_state
                    .last_bulk_packet_us
                    .saturating_sub(bulk_state.last_bulk_start_us);
            }
            bulk_state.in_bulk = false;
            bulk_state.last_bulk_bytes = 0;
            bulk_state.last_bulk_packets = 0;
            bulk_state.last_bulk_start_us = 0;
            bulk_state.last_bulk_packet_us = 0;
        }
    }

    pub fn duration_us(&self) -> u64 {
        self.last_time_us.saturating_sub(self.start_time_us)
    }

    pub fn packet_count(&self) -> usize {
        self.fwd_packets.len() + self.bwd_packets.len()
    }
}

/// Per-thread flow tracker. No locks — each XSK thread owns one.
/// RSS guarantees the same flow always goes to the same thread.
/// Uses LruCache for O(1) eviction instead of O(n) min_by_key scan.
pub struct FlowTracker {
    active: LruCache<FlowKey, FlowData>,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        // SAFETY: max(1, max_flows) ensures NonZero is never zero.
        let cap = NonZero::new(max_flows.max(1)).unwrap_or_else(|| unreachable!());
        Self {
            active: LruCache::new(cap),
        }
    }

    pub fn process_packet(&mut self, mut packet: UserPacket, is_ingress: bool) {
        let packet_key = FlowKey::from_packet(&packet);
        let reversed_key = packet_key.reverse();

        // Try to match an existing flow first (canonical key already established).
        // Use peek() to avoid promoting — we'll promote via get_mut() below.
        let (actual_key, is_forward) = if self.active.peek(&packet_key).is_some() {
            (packet_key, true)
        } else if self.active.peek(&reversed_key).is_some() {
            (reversed_key, false)
        } else {
            // New flow: determine initiator using TCP flags, fall back to is_ingress.
            let syn = packet.tcp_flags & TCP_SYN != 0;
            let ack = packet.tcp_flags & TCP_ACK != 0;
            if syn && ack {
                // SYN+ACK: sender is the responder.
                //   Ingress: external server responding to internal client → reverse so
                //            canonical key has internal client as src.
                //   Egress:  internal server responding to external client → keep as-is.
                if is_ingress {
                    (reversed_key, false)
                } else {
                    (packet_key, true)
                }
            } else if syn {
                // SYN: sender is always the initiator.
                (packet_key, true)
            } else {
                // Mid-stream / UDP / ICMP: use is_ingress as best-effort heuristic.
                // Egress = we are the initiator (forward); ingress = remote initiated (backward).
                if is_ingress {
                    (reversed_key, false)
                } else {
                    (packet_key, true)
                }
            }
        };

        packet.is_forward = is_forward;

        // Record which interface the initiator is on for this flow.
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

        // LruCache::push handles eviction automatically when capacity is exceeded (O(1)).
        // If the flow already exists, get_mut promotes it to MRU; otherwise push creates it.
        if let Some(flow) = self.active.get_mut(&actual_key) {
            flow.add_packet(&packet);
        } else {
            let mut flow = FlowData::new(actual_key.clone(), &packet, initiator_direction);
            flow.add_packet(&packet);
            self.active.push(actual_key, flow);
        }
    }

    /// Get all active flows (clone, no drain). Used by WebSocket.
    pub fn get_flows(&self) -> Vec<FlowData> {
        self.active.iter().map(|(_, flow)| flow.clone()).collect()
    }

    /// Get flows that received new packets since their last inference,
    /// and mark them as inferred. Used by ML engine.
    pub fn get_uninferred_flows(&mut self) -> Vec<FlowData> {
        let mut result = Vec::new();
        // iter_mut does NOT promote entries (preserves LRU order)
        for (_, flow) in self.active.iter_mut() {
            if flow.last_time_us > flow.last_inferred_us {
                result.push(flow.clone());
                flow.last_inferred_us = flow.last_time_us;
            }
        }
        result
    }

    pub fn flow_count(&self) -> usize {
        self.active.len()
    }

    /// Remove flows that have been idle too long or are terminated (FIN/RST seen).
    /// `now_us`: current timestamp in microseconds (same scale as packet timestamps).
    /// Returns the number of flows removed.
    pub fn cleanup_stale_flows(&mut self, now_us: u64) -> usize {
        // LruCache doesn't have retain(), so collect keys to remove then pop them.
        let keys_to_remove: Vec<FlowKey> = self
            .active
            .iter()
            .filter(|(_, flow)| {
                let idle = now_us.saturating_sub(flow.last_time_us);
                let is_terminated = flow.fin_count > 0 || flow.rst_count > 0;
                if is_terminated {
                    idle >= FLOW_TERMINATED_TIMEOUT_US
                } else {
                    idle >= FLOW_IDLE_TIMEOUT_US
                }
            })
            .map(|(k, _)| k.clone())
            .collect();
        let removed = keys_to_remove.len();
        for key in keys_to_remove {
            self.active.pop(&key);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(timestamp_us: u64, tcp_flags: u8) -> UserPacket {
        UserPacket {
            ip_version: 4,
            protocol: 6, // TCP
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

    #[test]
    fn cleanup_removes_idle_flows() {
        let mut tracker = FlowTracker::new(10000);
        let base_ts = 1_000_000_000u64; // 1000 seconds

        // Insert a flow with old timestamp
        let pkt = make_packet(base_ts, 0x02); // SYN
        tracker.process_packet(pkt, false);
        assert_eq!(tracker.flow_count(), 1);

        // 130 seconds later — should be cleaned up (idle > 120s)
        let now = base_ts + 130_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 1);
        assert_eq!(tracker.flow_count(), 0);
    }

    #[test]
    fn cleanup_keeps_active_flows() {
        let mut tracker = FlowTracker::new(10000);
        let base_ts = 1_000_000_000u64;

        let pkt = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt, false);

        // Only 10 seconds later — should NOT be cleaned up
        let now = base_ts + 10_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 0);
        assert_eq!(tracker.flow_count(), 1);
    }

    #[test]
    fn cleanup_removes_terminated_flows_after_short_idle() {
        let mut tracker = FlowTracker::new(10000);
        let base_ts = 1_000_000_000u64;

        // SYN packet
        let pkt1 = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt1, false);

        // FIN packet 1 second later
        let pkt2 = make_packet(base_ts + 1_000_000, 0x01); // FIN
        tracker.process_packet(pkt2, false);

        // 6 seconds after FIN — terminated flow should be removed (idle > 5s)
        let now = base_ts + 7_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 1);
        assert_eq!(tracker.flow_count(), 0);
    }

    #[test]
    fn cleanup_keeps_recently_terminated_flows() {
        let mut tracker = FlowTracker::new(10000);
        let base_ts = 1_000_000_000u64;

        let pkt1 = make_packet(base_ts, 0x02);
        tracker.process_packet(pkt1, false);

        // FIN packet
        let pkt2 = make_packet(base_ts + 1_000_000, 0x01);
        tracker.process_packet(pkt2, false);

        // Only 2 seconds after FIN — should still be around
        let now = base_ts + 3_000_000;
        let removed = tracker.cleanup_stale_flows(now);
        assert_eq!(removed, 0);
        assert_eq!(tracker.flow_count(), 1);
    }
}
