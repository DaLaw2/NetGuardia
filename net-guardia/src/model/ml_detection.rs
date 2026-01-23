use serde::{Deserialize, Serialize};
use tract_onnx::prelude::{Graph, SimplePlan, TypedFact, TypedOp};
use network_types::ip::IpProto;

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
    pub mean: f64,
    pub std: f64,
    pub median: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub protocol: IpProto,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub packet_length: u32,
    pub payload_length: u32,
    pub header_length: u16,
    pub timestamp_us: u64,
    pub tcp_flags: TcpFlags,
    pub tcp_window_size: u16,
    pub is_forward: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_byte(flags: u8) -> Self {
        Self {
            fin: (flags & 0x01) != 0,
            syn: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            psh: (flags & 0x08) != 0,
            ack: (flags & 0x10) != 0,
            urg: (flags & 0x20) != 0,
            ece: (flags & 0x40) != 0,
            cwr: (flags & 0x80) != 0,
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    pub fn from_packet(packet: &PacketInfo) -> Self {
        Self {
            src_ip: packet.src_ip.clone(),
            dst_ip: packet.dst_ip.clone(),
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            protocol: packet.protocol as u8,
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
    pub last_bulk_bytes: u64,
    pub last_bulk_packets: u64,
    pub in_bulk: bool,
}


