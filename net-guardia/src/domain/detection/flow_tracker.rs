use net_guardia_abi::define::tcp_flags::*;

use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::user_packet::UserPacket;
use crate::domain::detection::feature_extractor::FeatureStats;
use crate::domain::detection::ml_detection::{BulkState, FlowKey, PacketData};

#[derive(Debug, Clone, Copy)]
pub struct FlowLimits {
    pub max_packets_per_direction: usize,
    pub max_periods: usize,
    pub idle_threshold_us: u64,
    pub bulk_min_packets: u64,
    pub bulk_min_bytes: u64,
    pub idle_timeout_us: u64,
    pub terminated_timeout_us: u64,
}

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
    pub is_first_packet: bool,
}

#[derive(Debug, Clone)]
pub struct FlowSnapshot {
    pub flow_key: FlowKey,
    pub direction: Direction,
    pub start_time_us: u64,
    pub last_time_us: u64,
    pub packet_count: usize,
    pub fwd_packet_count: usize,
    pub bwd_packet_count: usize,
    pub total_bytes: u64,
    pub feature_stats: FeatureStats,
}

impl FlowSnapshot {
    pub fn from_flow_data(flow: &FlowData) -> Self {
        Self {
            flow_key: flow.flow_key,
            direction: flow.direction,
            start_time_us: flow.start_time_us,
            last_time_us: flow.last_time_us,
            packet_count: flow.packet_count(),
            fwd_packet_count: flow.fwd_packets.len(),
            bwd_packet_count: flow.bwd_packets.len(),
            total_bytes: flow.fwd_total_bytes + flow.bwd_total_bytes,
            feature_stats: FeatureStats::compute(flow),
        }
    }

    pub fn duration_us(&self) -> u64 {
        self.last_time_us.saturating_sub(self.start_time_us)
    }
}

impl FlowData {
    pub fn new(flow_key: FlowKey, first_packet: &UserPacket, direction: Direction) -> Self {
        Self {
            flow_key,
            direction,
            start_time_us: first_packet.timestamp_us,
            last_time_us: first_packet.timestamp_us,
            fwd_packets: Vec::with_capacity(32),
            fwd_total_bytes: 0,
            fwd_header_bytes: 0,
            bwd_packets: Vec::with_capacity(32),
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
            active_periods: Vec::with_capacity(16),
            idle_periods: Vec::with_capacity(8),
            last_packet_time: first_packet.timestamp_us,
            fwd_bulk_state: BulkState::default(),
            bwd_bulk_state: BulkState::default(),
            act_data_pkt_fwd: 0,
            is_first_packet: true,
        }
    }

    pub fn add_packet(&mut self, packet: &UserPacket, limits: &FlowLimits) {
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

        if iat > limits.idle_threshold_us {
            if self.idle_periods.len() < limits.max_periods {
                self.idle_periods.push(iat);
            }
        } else if iat > 0 && self.active_periods.len() < limits.max_periods {
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
            if self.fwd_packets.len() < limits.max_packets_per_direction {
                self.fwd_packets.push(packet_data);
            }
            self.fwd_total_bytes += packet.packet_length as u64;
            self.fwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_fwd == 0 {
                self.init_win_bytes_fwd = packet.tcp_window_size;
            }
            Self::update_bulk_state(&mut self.fwd_bulk_state, &packet_data, limits);
        } else {
            if self.bwd_packets.len() < limits.max_packets_per_direction {
                self.bwd_packets.push(packet_data);
            }
            self.bwd_total_bytes += packet.packet_length as u64;
            self.bwd_header_bytes += packet.header_length as u64;
            if self.init_win_bytes_bwd == 0 {
                self.init_win_bytes_bwd = packet.tcp_window_size;
            }
            Self::update_bulk_state(&mut self.bwd_bulk_state, &packet_data, limits);
        }
    }

    fn update_bulk_state(bulk_state: &mut BulkState, packet: &PacketData, limits: &FlowLimits) {
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
                && bulk_state.last_bulk_packets >= limits.bulk_min_packets
                && bulk_state.last_bulk_bytes >= limits.bulk_min_bytes
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
