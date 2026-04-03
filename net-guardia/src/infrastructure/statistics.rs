use std::sync::Arc;
use std::time;

use crate::core::ml::engine::Engine;
use crate::core::ml::flow_tracker::FlowData;
use crate::model::direction::Direction;
use crate::model::flow_stats::{FlowPushPayload, FlowStatsEntry, FlowSubscription, FlowSummary, StatsSummary};

/// Conversion from core::ml::FlowData to model::FlowStatsEntry.
/// Placed here (core layer) to maintain dependency rule: model/ must not import core/.
impl From<&FlowData> for FlowStatsEntry {
    fn from(flow: &FlowData) -> Self {
        Self {
            direction: flow.direction,
            ip_version: flow.flow_key.ip_version,
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

pub struct FlowStatistics {
    engine: Arc<Engine>,
}

impl FlowStatistics {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    pub fn get_all_flows(&self) -> Vec<FlowStatsEntry> {
        let mut entries = Vec::new();
        for tracker in self.engine.trackers() {
            let t = tracker.lock();
            entries.extend(t.get_flows().iter().map(FlowStatsEntry::from));
        }
        entries
    }

    pub fn get_filtered_flows(&self, sub: &FlowSubscription) -> Vec<FlowStatsEntry> {
        let now_us = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);

        let mut flows = self.get_all_flows();

        if let Some(dir) = &sub.direction {
            flows.retain(|f| &f.direction == dir);
        }

        if let Some(window_secs) = sub.window_secs {
            let cutoff = now_us.saturating_sub(window_secs * 1_000_000);
            flows.retain(|f| f.last_seen_us >= cutoff);
        }

        flows.sort_by(|a, b| (b.fwd_bytes + b.bwd_bytes).cmp(&(a.fwd_bytes + a.bwd_bytes)));

        if let Some(n) = sub.top_n {
            flows.truncate(n.min(10000));
        }

        flows
    }

    pub fn get_top_flows(&self, n: usize) -> Vec<FlowStatsEntry> {
        self.get_filtered_flows(&FlowSubscription {
            direction: None,
            window_secs: None,
            top_n: Some(n),
            interval_secs: None,
        })
    }

    pub fn get_flow_payload(&self, sub: &FlowSubscription) -> FlowPushPayload {
        let flows = self.get_filtered_flows(sub);
        let window_secs = sub.window_secs.unwrap_or(60).max(1);

        let mut ingress_bytes_v4: u64 = 0;
        let mut egress_bytes_v4: u64 = 0;
        let mut ingress_bytes_v6: u64 = 0;
        let mut egress_bytes_v6: u64 = 0;

        for f in &flows {
            let bytes = f.fwd_bytes + f.bwd_bytes;
            match (f.direction, f.ip_version) {
                (Direction::Ingress, 6) => ingress_bytes_v6 += bytes,
                (Direction::Ingress, _) => ingress_bytes_v4 += bytes,
                (Direction::Egress, 6) => egress_bytes_v6 += bytes,
                (Direction::Egress, _) => egress_bytes_v4 += bytes,
            }
        }

        let now_ms = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let summary = FlowSummary {
            ingress_bps_v4: ingress_bytes_v4 / window_secs,
            egress_bps_v4: egress_bytes_v4 / window_secs,
            ingress_bps_v6: ingress_bytes_v6 / window_secs,
            egress_bps_v6: egress_bytes_v6 / window_secs,
            total_flows: flows.len(),
            window_secs,
            timestamp_ms: now_ms,
        };

        FlowPushPayload { summary, flows }
    }

    pub fn get_summary(&self) -> StatsSummary {
        let flows = self.get_all_flows();
        let total_flows = flows.len();
        let total_bytes: u64 = flows.iter().map(|f| f.fwd_bytes + f.bwd_bytes).sum();
        let total_packets: usize = flows.iter().map(|f| f.fwd_packets + f.bwd_packets).sum();
        StatsSummary {
            total_flows,
            total_bytes,
            total_packets,
        }
    }
}
