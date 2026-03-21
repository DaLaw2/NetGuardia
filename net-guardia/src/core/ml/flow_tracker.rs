use std::collections::HashMap;
use common::define::tcp_flags::*;

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
            init_win_bytes_fwd: if first_packet.is_forward { first_packet.tcp_window_size } else { 0 },
            init_win_bytes_bwd: if !first_packet.is_forward { first_packet.tcp_window_size } else { 0 },
            active_periods: Vec::new(),
            idle_periods: Vec::new(),
            last_packet_time: first_packet.timestamp_us,
            fwd_bulk_state: BulkState::default(),
            bwd_bulk_state: BulkState::default(),
            act_data_pkt_fwd: 0,
            is_first_packet: true,
        }
    }

    pub fn add_packet(&mut self, packet: &UserPacket) {
        const MAX_PACKETS_PER_DIRECTION: usize = 1000;
        const MAX_PERIODS: usize = 10000;

        let packet_data = PacketData {
            timestamp_us: packet.timestamp_us,
            length: packet.packet_length,
            header_length: packet.header_length,
            payload_length: packet.payload_length,
            flags: packet.tcp_flags,
        };

        if packet.tcp_flags & TCP_FIN != 0 { self.fin_count += 1; }
        if packet.tcp_flags & TCP_SYN != 0 { self.syn_count += 1; }
        if packet.tcp_flags & TCP_RST != 0 { self.rst_count += 1; }
        if packet.tcp_flags & TCP_PSH != 0 { self.psh_count += 1; }
        if packet.tcp_flags & TCP_ACK != 0 { self.ack_count += 1; }
        if packet.tcp_flags & TCP_URG != 0 { self.urg_count += 1; }
        if packet.tcp_flags & TCP_CWR != 0 { self.cwe_count += 1; }
        if packet.tcp_flags & TCP_ECE != 0 { self.ece_count += 1; }

        let iat = packet.timestamp_us.saturating_sub(self.last_packet_time);
        const IDLE_THRESHOLD_US: u64 = 1_000_000;

        if iat > IDLE_THRESHOLD_US {
            if self.idle_periods.len() < MAX_PERIODS { self.idle_periods.push(iat); }
        } else if iat > 0
            && self.active_periods.len() < MAX_PERIODS { self.active_periods.push(iat); }

        self.last_packet_time = packet.timestamp_us;
        self.last_time_us = packet.timestamp_us;

        if self.is_first_packet {
            self.is_first_packet = false;
        } else if packet.is_forward && packet.payload_length > 0 {
            self.act_data_pkt_fwd += 1;
        }

        if packet.is_forward {
            if self.fwd_packets.len() < MAX_PACKETS_PER_DIRECTION {
                self.fwd_packets.push(packet_data.clone());
            }
            self.fwd_total_bytes += packet.payload_length as u64;
            self.fwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_fwd == 0 { self.init_win_bytes_fwd = packet.tcp_window_size; }
            Self::update_bulk_state(&mut self.fwd_bulk_state, &packet_data);
        } else {
            if self.bwd_packets.len() < MAX_PACKETS_PER_DIRECTION {
                self.bwd_packets.push(packet_data.clone());
            }
            self.bwd_total_bytes += packet.payload_length as u64;
            self.bwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_bwd == 0 { self.init_win_bytes_bwd = packet.tcp_window_size; }
            Self::update_bulk_state(&mut self.bwd_bulk_state, &packet_data);
        }
    }

    fn update_bulk_state(bulk_state: &mut BulkState, packet: &PacketData) {
        const BULK_MIN_PACKETS: u64 = 4;
        const BULK_MIN_BYTES: u64 = 1000;

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
                && bulk_state.last_bulk_packets >= BULK_MIN_PACKETS
                && bulk_state.last_bulk_bytes >= BULK_MIN_BYTES
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
pub struct FlowTracker {
    active: HashMap<FlowKey, FlowData>,
    max_flows: usize,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            active: HashMap::new(),
            max_flows,
        }
    }

    /// Swap active flows with an empty map and return the old one.
    /// This is O(1) — the caller filters outside the lock.
    pub fn take_snapshot(&mut self) -> HashMap<FlowKey, FlowData> {
        let mut snapshot = HashMap::with_capacity(self.active.capacity());
        std::mem::swap(&mut self.active, &mut snapshot);
        snapshot
    }

    pub fn process_packet(&mut self, mut packet: UserPacket, is_ingress: bool) {
        let packet_key = FlowKey::from_packet(&packet);
        let reversed_key = packet_key.clone().reverse();

        // Try to match an existing flow first (canonical key already established).
        let (actual_key, is_forward) = if self.active.contains_key(&packet_key) {
            (packet_key, true)
        } else if self.active.contains_key(&reversed_key) {
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
                if is_ingress { (reversed_key, false) } else { (packet_key, true) }
            } else if syn {
                // SYN: sender is always the initiator.
                (packet_key, true)
            } else {
                // Mid-stream / UDP / ICMP: use is_ingress as best-effort heuristic.
                // Egress = we are the initiator (forward); ingress = remote initiated (backward).
                if is_ingress { (reversed_key, false) } else { (packet_key, true) }
            }
        };

        packet.is_forward = is_forward;

        // Record which interface the initiator is on for this flow.
        let initiator_direction = if is_forward {
            if is_ingress { Direction::Ingress } else { Direction::Egress }
        } else {
            if is_ingress { Direction::Egress } else { Direction::Ingress }
        };

        let flow = self.active
            .entry(actual_key.clone())
            .or_insert_with(|| FlowData::new(actual_key, &packet, initiator_direction));

        flow.add_packet(&packet);

        if self.active.len() > self.max_flows
            && let Some(oldest_key) = self.active.iter()
                .min_by_key(|(_, flow)| flow.last_time_us)
                .map(|(k, _)| k.clone())
        {
            self.active.remove(&oldest_key);
        }
    }

    /// Get a snapshot without draining.
    pub fn get_flows(&self) -> Vec<FlowData> {
        self.active.values().cloned().collect()
    }

    pub fn flow_count(&self) -> usize {
        self.active.len()
    }
}

