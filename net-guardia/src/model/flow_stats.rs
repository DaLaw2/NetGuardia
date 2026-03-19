use serde::Serialize;

use crate::core::ml::flow_tracker::FlowData;

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatsEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub fwd_packets: usize,
    pub bwd_packets: usize,
    pub fwd_bytes: u64,
    pub bwd_bytes: u64,
    pub duration_us: u64,
}

impl From<&FlowData> for FlowStatsEntry {
    fn from(flow: &FlowData) -> Self {
        Self {
            src_ip: flow.flow_key.src_ip_string(),
            dst_ip: flow.flow_key.dst_ip_string(),
            src_port: flow.flow_key.src_port,
            dst_port: flow.flow_key.dst_port,
            protocol: flow.flow_key.protocol,
            fwd_packets: flow.fwd_packets.len(),
            bwd_packets: flow.bwd_packets.len(),
            fwd_bytes: flow.fwd_total_bytes,
            bwd_bytes: flow.bwd_total_bytes,
            duration_us: flow.duration_us(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSummary {
    pub total_flows: usize,
    pub total_bytes: u64,
    pub total_packets: usize,
}
