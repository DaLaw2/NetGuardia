use std::sync::Arc;

use tokio::sync::broadcast;

use crate::core::ml::engine::Engine;
use crate::model::flow_stats::{FlowStatsEntry, StatsSummary};

pub struct FlowStatistics {
    engine: Arc<Engine>,
    broadcast_tx: broadcast::Sender<Vec<FlowStatsEntry>>,
}

impl FlowStatistics {
    pub fn new(engine: Arc<Engine>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(16);
        Self { engine, broadcast_tx }
    }

    pub fn get_all_flows(&self) -> Vec<FlowStatsEntry> {
        let mut entries = Vec::new();
        for tracker in self.engine.trackers() {
            let t = tracker.lock();
            entries.extend(t.get_flows().iter().map(FlowStatsEntry::from));
        }
        entries
    }

    pub fn get_top_flows(&self, n: usize) -> Vec<FlowStatsEntry> {
        let n = n.min(10000);
        let mut flows = self.get_all_flows();
        flows.sort_by(|a, b| {
            (b.fwd_bytes + b.bwd_bytes).cmp(&(a.fwd_bytes + a.bwd_bytes))
        });
        flows.truncate(n);
        flows
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

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<FlowStatsEntry>> {
        self.broadcast_tx.subscribe()
    }

    pub fn broadcast(&self) {
        if self.broadcast_tx.receiver_count() > 0 {
            let flows = self.get_all_flows();
            let _ = self.broadcast_tx.send(flows);
        }
    }
}
