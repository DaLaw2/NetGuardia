use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time;

use crate::model::ml_detection::{BulkState, FlowKey, PacketData};
use common::model::event::Event;

#[derive(Debug, Clone)]
pub struct FlowData {
    pub flow_key: FlowKey,
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
    pub fn new(flow_key: FlowKey, first_packet: &Event) -> Self {
        Self {
            flow_key,
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
            } else {
                bulk_state.last_bulk_bytes += packet.length as u64;
                bulk_state.last_bulk_packets += 1;
            }
        } else {
            if bulk_state.in_bulk
                && bulk_state.last_bulk_packets >= BULK_MIN_PACKETS
                && bulk_state.last_bulk_bytes >= BULK_MIN_BYTES
            {
                bulk_state.bulk_count += 1;
                bulk_state.total_bytes += bulk_state.last_bulk_bytes;
                bulk_state.total_packets += bulk_state.last_bulk_packets;
            }
            bulk_state.in_bulk = false;
            bulk_state.last_bulk_bytes = 0;
            bulk_state.last_bulk_packets = 0;
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

    pub fn process_packet(&self, mut packet: Event) {
        let flow_key = FlowKey::from_packet(&packet);
        let reverse_key = flow_key.reverse();

        let Ok(mut flows) = self.flows.lock() else {
            return;
        };

        let (actual_key, is_forward) = if flows.contains_key(&flow_key) {
            (flow_key, true)
        } else if flows.contains_key(&reverse_key) {
            (reverse_key, false)
        } else {
            (flow_key, true)
        };

        packet.set_is_forward(is_forward);

        let flow = flows.entry(actual_key.clone()).or_insert_with(|| {
            FlowData::new(actual_key, &packet)
        });

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
        flows.retain(|_, flow| {
            now.saturating_sub(flow.last_time_us) < max_age_us
        });
    }

    pub fn flow_count(&self) -> usize {
        let Ok(flows) = self.flows.lock() else {
            return 0;
        };
        flows.len()
    }
}