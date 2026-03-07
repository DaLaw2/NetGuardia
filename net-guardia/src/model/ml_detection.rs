use common::model::event::{Event, TcpFlags};
use serde::{Deserialize, Serialize};
use tract_onnx::prelude::{Graph, SimplePlan, TypedFact, TypedOp};

use crate::model::direction::Direction;
use crate::utils::packet_parser::{format_ipv4, format_ipv6};

pub type RunnableModel = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipParams {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AENormalization {
    pub min: f64,
    pub max: f64,
    pub norm_max: f64,
    pub mean: f64,
    pub std: f64,
    pub median: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecisionLevels {
    pub threshold: f64,
    pub precision: f64,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn from_packet(packet: &Event) -> Self {
        match packet {
            Event::IPv4(ipv4) => Self {
                src_ip: format_ipv4(ipv4.src_ip),
                dst_ip: format_ipv4(ipv4.dst_ip),
                src_port: ipv4.src_port,
                dst_port: ipv4.dst_port,
                protocol: ipv4.protocol as u8,
            },
            Event::IPv6(ipv6) => Self {
                src_ip: format_ipv6(ipv6.src_ip),
                dst_ip: format_ipv6(ipv6.dst_ip),
                src_port: ipv6.src_port,
                dst_port: ipv6.dst_port,
                protocol: ipv6.protocol as u8,
            },
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip.clone(),
            dst_ip: self.src_ip.clone(),
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketData {
    pub timestamp_us: u64,
    pub length: u32,
    pub header_length: u16,
    pub payload_length: u32,
    pub flags: TcpFlags,
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

#[derive(Debug, Clone)]
pub struct EngineStats {
    pub active_flows: usize,
}
