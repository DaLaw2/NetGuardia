use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::domain::data_plane::direction::Direction;
use crate::domain::data_plane::ip_version::IpVersion;
use crate::domain::data_plane::user_packet::UserPacket;
use crate::domain::detection::attack_type::CanonicalAttackType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipParams {
    pub lower: f64,
    pub upper: f64,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: IpVersion,
}

impl FlowKey {
    pub fn from_packet(packet: &UserPacket) -> Self {
        Self {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol,
            ip_version: packet.ip_version,
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

    fn ip_bytes_to_string(&self, bytes: &[u8; 16]) -> String {
        if self.ip_version.is_v6() {
            Ipv6Addr::from(*bytes).to_string()
        } else {
            let octets: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
            Ipv4Addr::from(octets).to_string()
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
    pub attack_type: Option<CanonicalAttackType>,
    pub confidence: f32,
    pub alert_threshold: f32,
    pub ae_score: f32,
    pub anomaly_score: f32,
    pub c2_score: f32,
    pub packet_count: u64,
    pub flow_duration_us: u64,
}

#[derive(Debug, Clone, Default)]
pub struct InferenceStats {
    pub total_flows: usize,
    pub malicious_flows: usize,
    pub benign_flows: usize,
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
            flows_per_second: fps,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertMessage {
    pub timestamp: u64,
    pub flow_key: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub is_attack: bool,
    pub attack_type: Option<String>,
    pub confidence: f32,
    pub ae_score: f32,
    pub anomaly_score: f32,
    pub c2_score: f32,
    pub packet_count: u64,
    pub flow_duration_us: u64,
}

impl AlertMessage {
    pub fn from_detection_result(result: &DetectionResult, timestamp: u64) -> Self {
        Self {
            timestamp,
            flow_key: result.flow_key.clone(),
            src_ip: result.flow_key_raw.src_ip_string(),
            dst_ip: result.flow_key_raw.dst_ip_string(),
            src_port: result.flow_key_raw.src_port,
            dst_port: result.flow_key_raw.dst_port,
            protocol: result.flow_key_raw.protocol,
            is_attack: result.is_attack,
            attack_type: result.attack_type.map(|attack_type| attack_type.to_string()),
            confidence: result.confidence,
            ae_score: result.ae_score,
            anomaly_score: result.anomaly_score,
            c2_score: result.c2_score,
            packet_count: result.packet_count,
            flow_duration_us: result.flow_duration_us,
        }
    }
}
