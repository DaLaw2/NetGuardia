use serde::{Deserialize, Serialize};

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

// NOTE: From<&FlowData> impl moved to core/infrastructure/statistics.rs
// to maintain the dependency rule: model/ must not import core/

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
