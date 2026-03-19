use std::collections::HashMap;
use std::time;

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
        } else if iat > 0 {
            if self.active_periods.len() < MAX_PERIODS { self.active_periods.push(iat); }
        }

        self.last_packet_time = packet.timestamp_us;
        self.last_time_us = packet.timestamp_us;

        if packet.is_forward {
            if self.fwd_packets.len() < MAX_PACKETS_PER_DIRECTION {
                self.fwd_packets.push(packet_data.clone());
            }
            self.fwd_total_bytes += packet.packet_length as u64;
            self.fwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_fwd == 0 { self.init_win_bytes_fwd = packet.tcp_window_size; }
            Self::update_bulk_state(&mut self.fwd_bulk_state, &packet_data);
        } else {
            if self.bwd_packets.len() < MAX_PACKETS_PER_DIRECTION {
                self.bwd_packets.push(packet_data.clone());
            }
            self.bwd_total_bytes += packet.packet_length as u64;
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
    flows: HashMap<FlowKey, FlowData>,
    max_flows: usize,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows,
        }
    }

    pub fn process_packet(&mut self, mut packet: UserPacket, is_ingress: bool, payload: &[u8]) {
        let direction = if is_ingress { Direction::Ingress } else { Direction::Egress };
        let packet_key = FlowKey::from_packet(&packet);
        let proto = packet_key.protocol;
        let src_port = packet_key.src_port;
        let dst_port = packet_key.dst_port;
        let reversed_key = packet_key.clone().reverse();

        let (actual_key, is_forward) = if self.flows.contains_key(&packet_key) {
            (packet_key, true)
        } else if self.flows.contains_key(&reversed_key) {
            (reversed_key, false)
        } else {
            let has_syn = packet.tcp_flags & TCP_SYN != 0;
            let has_ack = packet.tcp_flags & TCP_ACK != 0;
            if has_syn && has_ack {
                if is_ingress { (reversed_key, false) } else { (packet_key, true) }
            } else if has_syn {
                (packet_key, true)
            } else {
                match detect_initiator(payload, proto, src_port, dst_port) {
                    Some(true) => (packet_key, true),
                    Some(false) => (reversed_key, false),
                    None => (packet_key, true),
                }
            }
        };

        packet.is_forward = is_forward;
        let initiator_direction = if is_forward { direction } else { direction.flip() };

        let flow = self.flows
            .entry(actual_key.clone())
            .or_insert_with(|| FlowData::new(actual_key, &packet, initiator_direction));

        flow.add_packet(&packet);

        if self.flows.len() > self.max_flows {
            if let Some(oldest_key) = self.flows.iter()
                .min_by_key(|(_, flow)| flow.last_time_us)
                .map(|(k, _)| k.clone())
            {
                self.flows.remove(&oldest_key);
            }
        }
    }

    /// Take all flows out, leaving this tracker empty. Lock-free.
    pub fn drain_flows(&mut self) -> Vec<FlowData> {
        self.flows.drain().map(|(_, v)| v).collect()
    }

    /// Get a snapshot without draining.
    pub fn get_flows(&self) -> Vec<FlowData> {
        self.flows.values().cloned().collect()
    }

    pub fn get_flows_for_inference(&self, min_packets: usize) -> Vec<FlowData> {
        self.flows
            .values()
            .filter(|flow| flow.packet_count() >= min_packets)
            .cloned()
            .collect()
    }

    pub fn cleanup_old_flows(&mut self, max_age_us: u64) {
        let now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        self.flows.retain(|_, flow| now.saturating_sub(flow.last_time_us) < max_age_us);
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

fn detect_initiator(payload: &[u8], protocol: u8, src_port: u16, dst_port: u16) -> Option<bool> {
    if payload.is_empty() { return None; }

    if payload.len() >= 6 && payload[0] == 0x16 {
        return match payload[5] {
            0x01 => Some(true),
            0x02 => Some(false),
            _ => None,
        };
    }

    if payload.len() >= 5 {
        if payload.starts_with(b"GET ")
            || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ")
            || payload.starts_with(b"HEAD ")
            || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"OPTIONS ")
            || payload.starts_with(b"PATCH ")
        {
            return Some(true);
        }
        if payload.starts_with(b"HTTP/") {
            return Some(false);
        }
    }

    if protocol == 17 && (src_port == 53 || dst_port == 53) && payload.len() >= 3 {
        return Some((payload[2] >> 7) == 0);
    }

    None
}
