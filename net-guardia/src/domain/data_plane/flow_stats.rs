use serde::{Deserialize, Serialize};

use crate::domain::data_plane::direction::Direction;

#[derive(Debug, Clone, Copy)]
pub struct FlowStatsLimits {
    max_snapshot_entries: usize,
    max_top_n: usize,
}

impl FlowStatsLimits {
    pub fn new(max_snapshot_entries: usize, max_top_n: usize) -> Self {
        Self {
            max_snapshot_entries: max_snapshot_entries.max(1),
            max_top_n: max_top_n.max(1),
        }
    }

    pub fn result_limit(self, requested_top_n: Option<usize>) -> usize {
        requested_top_n
            .unwrap_or(self.max_snapshot_entries)
            .max(1)
            .min(self.max_top_n)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowStatsEntry {
    pub direction: Direction,
    pub ip_version: u8,
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

// NOTE: From<&FlowData> impl lives in infrastructure/statistics.rs so
// model/ doesn't need to import core/ (dependency-rule invariant).

#[derive(Debug, Clone, Serialize)]
pub struct StatsSummary {
    pub total_flows: usize,
    pub total_bytes: u64,
    pub total_packets: usize,
}

/// Real-time throughput summary pushed via WebSocket alongside flow data.
/// Rates are calculated server-side using actual elapsed time.
#[derive(Debug, Clone, Serialize)]
pub struct FlowSummary {
    pub ingress_bps_v4: u64,
    pub egress_bps_v4: u64,
    pub ingress_bps_v6: u64,
    pub egress_bps_v6: u64,
    pub total_flows: usize,
    pub window_secs: u64,
    pub timestamp_ms: u64,
}

/// Combined payload for the flow WebSocket: summary + individual flows.
#[derive(Debug, Clone, Serialize)]
pub struct FlowPushPayload {
    pub summary: FlowSummary,
    pub flows: Vec<FlowStatsEntry>,
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

#[cfg(test)]
mod tests {
    use super::FlowStatsLimits;

    #[test]
    fn result_limit_uses_snapshot_default_when_top_n_absent() {
        let limits = FlowStatsLimits::new(128, 1024);

        assert_eq!(limits.result_limit(None), 128);
    }

    #[test]
    fn result_limit_caps_requested_top_n() {
        let limits = FlowStatsLimits::new(128, 256);

        assert_eq!(limits.result_limit(Some(1_000)), 256);
    }

    #[test]
    fn result_limit_never_returns_zero() {
        let limits = FlowStatsLimits::new(0, 0);

        assert_eq!(limits.result_limit(Some(0)), 1);
    }
}
