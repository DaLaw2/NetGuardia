use serde::{Deserialize, Serialize};

use crate::core::ml::flow_tracker::FlowData;
use crate::model::direction::Direction;

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatsEntry {
    pub direction: Direction,
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
    pub last_seen_us: u64,
}

impl From<&FlowData> for FlowStatsEntry {
    fn from(flow: &FlowData) -> Self {
        Self {
            direction: flow.direction,
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
            last_seen_us: flow.last_time_us,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSummary {
    pub total_flows: usize,
    pub total_bytes: u64,
    pub total_packets: usize,
}

/// Client subscription filter for WebSocket flow stats
#[derive(Debug, Clone, Deserialize)]
pub struct FlowSubscription {
    /// Filter by direction: "ingress", "egress", or null for both
    pub direction: Option<Direction>,
    /// Time window in seconds: only flows with last_seen within this window
    pub window_secs: Option<u64>,
    /// Max number of flows to return (sorted by bytes desc)
    pub top_n: Option<usize>,
    /// Push interval in seconds (default 5)
    pub interval_secs: Option<u64>,
}
