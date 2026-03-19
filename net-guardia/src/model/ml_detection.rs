use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use tract_onnx::prelude::{Graph, SimplePlan, TypedFact, TypedOp};

use crate::model::direction::Direction;
use crate::model::user_packet::UserPacket;

pub type RunnableModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct EngineConfig {
    pub max_flows: usize,
    pub min_packets: usize,
    pub batch_size: usize,
    pub inference_interval_secs: u64,
    pub aggregator_window_secs: u64,
    pub flow_timeout_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipParams {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: u8,
}

impl FlowKey {
    pub fn from_packet(packet: &UserPacket) -> Self {
        let (src_ip, ip_version) = Self::parse_ip_to_bytes(&packet.src_ip);
        let (dst_ip, _) = Self::parse_ip_to_bytes(&packet.dst_ip);
        Self {
            src_ip,
            dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
            ip_version,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            ip_version: self.ip_version,
        }
    }

    pub fn src_ip_string(&self) -> String {
        self.ip_bytes_to_string(&self.src_ip)
    }

    pub fn dst_ip_string(&self) -> String {
        self.ip_bytes_to_string(&self.dst_ip)
    }

    fn parse_ip_to_bytes(ip_str: &str) -> ([u8; 16], u8) {
        if let Ok(addr) = ip_str.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(v4) => {
                    let mut buf = [0u8; 16];
                    buf[..4].copy_from_slice(&v4.octets());
                    (buf, 4)
                }
                IpAddr::V6(v6) => (v6.octets(), 6),
            }
        } else {
            ([0u8; 16], 4)
        }
    }

    fn ip_bytes_to_string(&self, bytes: &[u8; 16]) -> String {
        if self.ip_version == 6 {
            Ipv6Addr::from(*bytes).to_string()
        } else {
            let octets: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
            Ipv4Addr::from(octets).to_string()
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketData {
    pub timestamp_us: u64,
    pub length: u32,
    pub header_length: u16,
    pub payload_length: u32,
    pub flags: u8,
}

#[derive(Debug, Clone, Default)]
pub struct BulkState {
    pub bulk_count: u32,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub total_duration_us: u64,
    pub last_bulk_bytes: u64,
    pub last_bulk_packets: u64,
    pub last_bulk_start_us: u64,
    pub last_bulk_packet_us: u64,
    pub in_bulk: bool,
}

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub flow_key: String,
    pub flow_key_raw: FlowKey,
    pub direction: Direction,
    pub is_attack: bool,
    pub attack_type: Option<String>,
    pub confidence: f32,
    pub ae_score: f32,
    pub threshold: f32,
}

#[derive(Debug, Clone, Default)]
pub struct InferenceStats {
    pub total_flows: usize,
    pub malicious_flows: usize,
    pub benign_flows: usize,
    #[allow(dead_code)]
    pub inference_time_us: u64,
    pub flows_per_second: f32,
}

impl InferenceStats {
    pub fn from_results(results: &[DetectionResult], elapsed_us: u64) -> Self {
        let total = results.len();
        let malicious = results.iter().filter(|r| r.is_attack).count();
        let benign = total - malicious;

        let fps = if elapsed_us > 0 {
            (total as f64 / (elapsed_us as f64 / 1_000_000.0)) as f32
        } else {
            0.0
        };

        Self {
            total_flows: total,
            malicious_flows: malicious,
            benign_flows: benign,
            inference_time_us: elapsed_us,
            flows_per_second: fps,
        }
    }
}
