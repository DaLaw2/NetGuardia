use common::model::event::Event;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Helper trait for Event to extract common fields
pub trait EventExt {
    fn get_addresses(&self) -> (IpAddr, IpAddr, u16, u16);
    fn get_protocol(&self) -> u8;
    fn get_timestamp(&self) -> u64;
    fn get_len(&self) -> u32;
}

impl EventExt for Event {
    fn get_addresses(&self) -> (IpAddr, IpAddr, u16, u16) {
        match self {
            Event::IPv4(e) => (
                IpAddr::V4(std::net::Ipv4Addr::from(e.source_ip.to_be())),
                IpAddr::V4(std::net::Ipv4Addr::from(e.destination_ip.to_be())),
                e.source_port,
                e.destination_port,
            ),
            Event::IPv6(e) => (
                IpAddr::V6(std::net::Ipv6Addr::from(e.source_ip.to_be())),
                IpAddr::V6(std::net::Ipv6Addr::from(e.destination_ip.to_be())),
                e.source_port,
                e.destination_port,
            ),
        }
    }

    fn get_protocol(&self) -> u8 {
        match self {
            Event::IPv4(e) => e.protocol as u8,
            Event::IPv6(e) => e.protocol as u8,
        }
    }

    fn get_timestamp(&self) -> u64 {
        match self {
            Event::IPv4(e) => e.timestamp,
            Event::IPv6(e) => e.timestamp,
        }
    }

    fn get_len(&self) -> u32 {
        match self {
            Event::IPv4(e) => e.len,
            Event::IPv6(e) => e.len,
        }
    }
}

/// TCP Flags
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: u32,
    pub syn: u32,
    pub rst: u32,
    pub psh: u32,
    pub ack: u32,
    pub urg: u32,
    pub ece: u32,
    pub cwe: u32,
}

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

/// Packet information
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub length: u32,
    pub header_length: u32,
    pub tcp_flags: Option<TcpFlags>,
    pub direction: Direction,
}

/// Flow statistics for one direction
#[derive(Debug, Clone, Default)]
pub struct DirectionalStats {
    pub packets: u64,
    pub bytes: u64,
    pub header_bytes: u64,

    // Packet lengths
    pub packet_lengths: Vec<u32>,

    // Inter-arrival times (microseconds)
    pub iats: Vec<u64>,

    // TCP flags (if TCP)
    pub psh_flags: u32,
    pub urg_flags: u32,

    // Last packet timestamp
    pub last_timestamp: u64,
}

impl DirectionalStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_packet(&mut self, pkt: &PacketInfo) {
        self.packets += 1;
        self.bytes += pkt.length as u64;
        self.header_bytes += pkt.header_length as u64;
        self.packet_lengths.push(pkt.length);

        // Calculate IAT
        if self.last_timestamp > 0 {
            let iat = if pkt.timestamp > self.last_timestamp {
                pkt.timestamp - self.last_timestamp
            } else {
                0
            };
            self.iats.push(iat);
        }

        self.last_timestamp = pkt.timestamp;

        // TCP flags
        if let Some(flags) = &pkt.tcp_flags {
            self.psh_flags += flags.psh;
            self.urg_flags += flags.urg;
        }
    }
}

/// Bidirectional flow record
#[derive(Debug, Clone)]
pub struct FlowRecord {
    // Flow 5-tuple
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,

    // Flow ID (for tracking)
    pub flow_id: String,

    // Timestamps
    pub start_time: u64,  // microseconds since epoch
    pub last_seen: u64,   // microseconds since epoch

    // Directional statistics
    pub forward: DirectionalStats,
    pub backward: DirectionalStats,

    // TCP flags (total)
    pub tcp_flags: TcpFlags,

    // Active/Idle times tracking
    pub active_times: Vec<u64>,  // Duration of active periods (microseconds)
    pub idle_times: Vec<u64>,    // Duration of idle periods (microseconds)
    pub last_activity_time: u64,
    pub is_active: bool,

    // Bulk transfer tracking
    pub fwd_bulk_state: BulkState,
    pub bwd_bulk_state: BulkState,
}

/// Bulk transfer state
#[derive(Debug, Clone, Default)]
pub struct BulkState {
    pub bulk_count: u32,
    pub bulk_bytes: u64,
    pub bulk_packets: u64,
    pub last_bulk_time: u64,
    pub in_bulk: bool,
}

impl FlowRecord {
    /// Create a new flow record from the first packet
    pub fn new(event: &Event) -> Self {
        let (src_ip, dst_ip, src_port, dst_port) = event.get_addresses();
        let protocol = event.get_protocol();
        let timestamp = event.get_timestamp();

        let flow_id = format!(
            "{}:{}-<>{}:{}:{}",
            src_ip, src_port, dst_ip, dst_port, protocol
        );

        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            flow_id,
            start_time: timestamp,
            last_seen: timestamp,
            forward: DirectionalStats::new(),
            backward: DirectionalStats::new(),
            tcp_flags: TcpFlags::default(),
            active_times: Vec::new(),
            idle_times: Vec::new(),
            last_activity_time: timestamp,
            is_active: true,
            fwd_bulk_state: BulkState::default(),
            bwd_bulk_state: BulkState::default(),
        }
    }

    /// Add a packet to this flow
    pub fn add_packet(&mut self, event: &Event) {
        let timestamp = event.get_timestamp();
        let length = event.get_len();

        // Determine direction
        let (src_ip, _, src_port, _) = event.get_addresses();
        let direction = if src_ip == self.src_ip && src_port == self.src_port {
            Direction::Forward
        } else {
            Direction::Backward
        };

        // Estimate header length (simplified)
        // TCP: 20-60 bytes, UDP: 8 bytes
        let header_length = match self.protocol {
            6 => 40,  // TCP (IP header 20 + TCP header 20)
            17 => 28, // UDP (IP header 20 + UDP header 8)
            _ => 20,  // Just IP header
        };

        // Extract TCP flags if TCP
        let tcp_flags = if self.protocol == 6 {
            // In real implementation, parse TCP header from packet data
            // For now, use placeholder
            Some(TcpFlags::default())
        } else {
            None
        };

        let pkt_info = PacketInfo {
            timestamp,
            length,
            header_length,
            tcp_flags: tcp_flags.clone(),
            direction,
        };

        // Update directional stats
        match direction {
            Direction::Forward => self.forward.add_packet(&pkt_info),
            Direction::Backward => self.backward.add_packet(&pkt_info),
        }

        // Update TCP flags
        if let Some(flags) = tcp_flags {
            self.tcp_flags.fin += flags.fin;
            self.tcp_flags.syn += flags.syn;
            self.tcp_flags.rst += flags.rst;
            self.tcp_flags.psh += flags.psh;
            self.tcp_flags.ack += flags.ack;
            self.tcp_flags.urg += flags.urg;
            self.tcp_flags.ece += flags.ece;
            self.tcp_flags.cwe += flags.cwe;
        }

        // Update active/idle times
        self.update_activity(timestamp);

        // Update bulk state
        self.update_bulk_state(&pkt_info);

        self.last_seen = timestamp;
    }

    /// Update active/idle time tracking
    fn update_activity(&mut self, timestamp: u64) {
        const ACTIVITY_THRESHOLD: u64 = 1_000_000; // 1 second in microseconds

        let time_diff = if timestamp > self.last_activity_time {
            timestamp - self.last_activity_time
        } else {
            0
        };

        if time_diff > ACTIVITY_THRESHOLD {
            // Period of inactivity
            if self.is_active {
                self.is_active = false;
            }
            self.idle_times.push(time_diff);
        } else {
            // Active period
            if !self.is_active {
                self.is_active = true;
            }
            if !self.active_times.is_empty() || timestamp > self.start_time {
                self.active_times.push(time_diff);
            }
        }

        self.last_activity_time = timestamp;
    }

    /// Update bulk transfer state
    fn update_bulk_state(&mut self, pkt: &PacketInfo) {
        const BULK_THRESHOLD: u32 = 512; // Minimum packet size for bulk
        const BULK_TIMEOUT: u64 = 1_000_000; // 1 second

        let state = match pkt.direction {
            Direction::Forward => &mut self.fwd_bulk_state,
            Direction::Backward => &mut self.bwd_bulk_state,
        };

        if pkt.length >= BULK_THRESHOLD {
            let time_diff = if pkt.timestamp > state.last_bulk_time {
                pkt.timestamp - state.last_bulk_time
            } else {
                0
            };

            if state.in_bulk && time_diff < BULK_TIMEOUT {
                // Continue bulk
                state.bulk_bytes += pkt.length as u64;
                state.bulk_packets += 1;
            } else {
                // Start new bulk
                if state.in_bulk {
                    state.bulk_count += 1;
                }
                state.in_bulk = true;
                state.bulk_bytes = pkt.length as u64;
                state.bulk_packets = 1;
            }

            state.last_bulk_time = pkt.timestamp;
        } else {
            // End bulk
            if state.in_bulk {
                state.bulk_count += 1;
                state.in_bulk = false;
            }
        }
    }

    /// Get flow duration in microseconds
    pub fn duration(&self) -> u64 {
        if self.last_seen >= self.start_time {
            self.last_seen - self.start_time
        } else {
            0
        }
    }

    /// Check if flow is expired (no activity for timeout period)
    pub fn is_expired(&self, timeout: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let timeout_us = timeout.as_micros() as u64;

        now.saturating_sub(self.last_seen) > timeout_us
    }

    /// Get flow key for hashing
    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            protocol: self.protocol,
        }
    }

    /// Get reverse flow key (for bidirectional matching)
    pub fn reverse_flow_key(&self) -> FlowKey {
        FlowKey {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

/// Flow key for hashing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Create canonical flow key (for bidirectional flow matching)
    pub fn canonical(&self) -> Self {
        // Order by IP address first, then port
        if self.src_ip < self.dst_ip {
            self.clone()
        } else if self.src_ip > self.dst_ip {
            FlowKey {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        } else {
            // Same IP, order by port
            if self.src_port <= self.dst_port {
                self.clone()
            } else {
                FlowKey {
                    src_ip: self.dst_ip,
                    dst_ip: self.src_ip,
                    src_port: self.dst_port,
                    dst_port: self.src_port,
                    protocol: self.protocol,
                }
            }
        }
    }
}