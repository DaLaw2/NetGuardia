use std::sync::Arc;
use std::time;

use crate::core::ml::engine::Engine;
use crate::model::flow_stats::{FlowStatsEntry, FlowSubscription, StatsSummary};

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

        flows.sort_by(|a, b| {
            (b.fwd_bytes + b.bwd_bytes).cmp(&(a.fwd_bytes + a.bwd_bytes))
        });

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
