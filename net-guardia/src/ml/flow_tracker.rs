use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time;

use common::model::event::Event;

use crate::model::direction::Direction;
use crate::model::ml_detection::{BulkState, FlowKey, PacketData};

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
    pub fn new(flow_key: FlowKey, first_packet: &Event, direction: Direction) -> Self {
        Self {
            flow_key,
            direction,
            start_time_us: first_packet.timestamp_us(),
            last_time_us: first_packet.timestamp_us(),
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
            init_win_bytes_fwd: if first_packet.is_forward() {
                first_packet.tcp_window_size()
            } else {
                0
            },
            init_win_bytes_bwd: if !first_packet.is_forward() {
                first_packet.tcp_window_size()
            } else {
                0
            },
            active_periods: Vec::new(),
            idle_periods: Vec::new(),
            last_packet_time: first_packet.timestamp_us(),
            fwd_bulk_state: BulkState::default(),
            bwd_bulk_state: BulkState::default(),
        }
    }

    pub fn add_packet(&mut self, packet: &Event) {
        let packet_data = PacketData {
            timestamp_us: packet.timestamp_us(),
            length: packet.packet_length(),
            header_length: packet.header_length(),
            payload_length: packet.payload_length(),
            flags: packet.tcp_flags().clone(),
        };

        if packet.tcp_flags().fin {
            self.fin_count += 1;
        }
        if packet.tcp_flags().syn {
            self.syn_count += 1;
        }
        if packet.tcp_flags().rst {
            self.rst_count += 1;
        }
        if packet.tcp_flags().psh {
            self.psh_count += 1;
        }
        if packet.tcp_flags().ack {
            self.ack_count += 1;
        }
        if packet.tcp_flags().urg {
            self.urg_count += 1;
        }
        if packet.tcp_flags().cwr {
            self.cwe_count += 1;
        }
        if packet.tcp_flags().ece {
            self.ece_count += 1;
        }

        let iat = packet.timestamp_us().saturating_sub(self.last_packet_time);
        const IDLE_THRESHOLD_US: u64 = 1_000_000;

        if iat > IDLE_THRESHOLD_US {
            self.idle_periods.push(iat);
        } else if iat > 0 {
            self.active_periods.push(iat);
        }

        self.last_packet_time = packet.timestamp_us();
        self.last_time_us = packet.timestamp_us();

        if packet.is_forward() {
            self.fwd_packets.push(packet_data.clone());
            self.fwd_total_bytes += packet.packet_length() as u64;
            self.fwd_header_bytes += packet.header_length() as u64;

            if self.init_win_bytes_fwd == 0 {
                self.init_win_bytes_fwd = packet.tcp_window_size();
            }

            Self::update_bulk_state(&mut self.fwd_bulk_state, &packet_data);
        } else {
            self.bwd_packets.push(packet_data.clone());
            self.bwd_total_bytes += packet.packet_length() as u64;
            self.bwd_header_bytes += packet.header_length() as u64;

            if self.init_win_bytes_bwd == 0 {
                self.init_win_bytes_bwd = packet.tcp_window_size();
            }

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

pub struct FlowTracker {
    flows: Arc<Mutex<HashMap<FlowKey, FlowData>>>,
    max_flows: usize,
}

impl FlowTracker {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: Arc::new(Mutex::new(HashMap::new())),
            max_flows,
        }
    }

    pub fn process_packet(&self, mut packet: Event, is_ingress: bool, payload: &[u8]) {
        let direction = if is_ingress {
            Direction::Ingress
        } else {
            Direction::Egress
        };
        let packet_key = FlowKey::from_packet(&packet);
        let proto = packet_key.protocol;
        let src_port = packet_key.src_port;
        let dst_port = packet_key.dst_port;
        let reversed_key = packet_key.clone().reverse();

        let Ok(mut flows) = self.flows.lock() else {
            return;
        };

        // Try-both: canonical key is whichever orientation already exists in the flow table.
        // For new flows, identify the initiator using (in priority order):
        //   1. TCP SYN / SYN+ACK flags
        //   2. DPI: TLS ClientHello/ServerHello, HTTP request/response, DNS QR bit
        //   3. Best effort: use packet as-is
        let (actual_key, is_forward) = if flows.contains_key(&packet_key) {
            (packet_key, true)
        } else if flows.contains_key(&reversed_key) {
            (reversed_key, false)
        } else {
            let flags = packet.tcp_flags();
            if flags.syn && flags.ack {
                // Normal: Server (egress side) sends SYN+ACK, packet arrives on ingress → reverse
                // Bot attack: Client (egress side) sends SYN+ACK, packet arrives on egress → keep as-is
                if is_ingress {
                    (reversed_key, false)
                } else {
                    (packet_key, true)
                }
            } else if flags.syn {
                (packet_key, true)
            } else {
                match detect_initiator(payload, proto, src_port, dst_port) {
                    Some(true) => (packet_key, true),
                    Some(false) => (reversed_key, false),
                    None => (packet_key, true),
                }
            }
        };

        packet.set_is_forward(is_forward);

        // `direction` should reflect the initiator's interface.
        // If this packet is backward (is_forward = false), the initiator is on the opposite side.
        let initiator_direction = if is_forward { direction } else { direction.flip() };

        let flow = flows
            .entry(actual_key.clone())
            .or_insert_with(|| FlowData::new(actual_key, &packet, initiator_direction));

        flow.add_packet(&packet);

        if flows.len() > self.max_flows {
            if let Some(key) = flows.keys().next().cloned() {
                flows.remove(&key);
            }
        }
    }

    pub fn get_flows_snapshot(&self) -> Vec<FlowData> {
        let Ok(flows) = self.flows.lock() else {
            return Vec::new();
        };
        flows.values().cloned().collect()
    }

    pub fn get_flows_for_inference(&self, min_packets: usize) -> Vec<FlowData> {
        let Ok(flows) = self.flows.lock() else {
            return Vec::new();
        };
        flows
            .values()
            .filter(|flow| flow.packet_count() >= min_packets)
            .cloned()
            .collect()
    }

    pub fn cleanup_old_flows(&self, max_age_us: u64) {
        let now = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let Ok(mut flows) = self.flows.lock() else {
            return;
        };
        flows.retain(|_, flow| now.saturating_sub(flow.last_time_us) < max_age_us);
    }

    pub fn flow_count(&self) -> usize {
        let Ok(flows) = self.flows.lock() else {
            return 0;
        };
        flows.len()
    }
}

/// Inspect payload bytes to determine which side is the flow initiator.
/// Returns Some(true) if this packet is from the initiator, Some(false) if from the responder,
/// or None if the payload gives no useful signal.
fn detect_initiator(payload: &[u8], protocol: u8, src_port: u16, dst_port: u16) -> Option<bool> {
    if payload.is_empty() {
        return None;
    }

    // TLS: record type 0x16 (Handshake), byte 5 = handshake type
    //   0x01 = ClientHello → this side is the initiator
    //   0x02 = ServerHello → this side is the responder
    if payload.len() >= 6 && payload[0] == 0x16 {
        return match payload[5] {
            0x01 => Some(true),
            0x02 => Some(false),
            _ => None,
        };
    }

    // HTTP: request line starts with a method verb (initiator),
    //       response starts with "HTTP/" (responder)
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

    // DNS over UDP (port 53): flags byte 2, MSB = QR bit
    //   0 = query (initiator), 1 = response (responder)
    if protocol == 17 && (src_port == 53 || dst_port == 53) && payload.len() >= 3 {
        return Some((payload[2] >> 7) == 0);
    }

    None
}
