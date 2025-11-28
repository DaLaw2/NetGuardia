use super::flow_record::{EventExt, FlowKey, FlowRecord};
use super::features::CicFeatures;
use common::model::event::Event;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Flow aggregator - manages bidirectional flows
pub struct FlowAggregator {
    /// Active flows (canonical key -> flow record)
    flows: Arc<RwLock<HashMap<FlowKey, FlowRecord>>>,

    /// Flow timeout (default: 120 seconds)
    flow_timeout: Duration,

    /// Maximum flows to track (prevent memory exhaustion)
    max_flows: usize,

    /// Callback for completed flows
    on_flow_complete: Option<Arc<dyn Fn(FlowRecord) + Send + Sync>>,
}

impl FlowAggregator {
    /// Create a new flow aggregator
    pub fn new(flow_timeout: Duration, max_flows: usize) -> Self {
        Self {
            flows: Arc::new(RwLock::new(HashMap::new())),
            flow_timeout,
            max_flows,
            on_flow_complete: None,
        }
    }

    /// Set callback for completed flows
    pub fn on_flow_complete<F>(&mut self, callback: F)
    where
        F: Fn(FlowRecord) + Send + Sync + 'static,
    {
        self.on_flow_complete = Some(Arc::new(callback));
    }

    /// Process a packet event
    pub fn process_event(&self, event: &Event) {
        let mut flows = self.flows.write();

        // Create flow key
        let (src_ip, dst_ip, src_port, dst_port) = event.get_addresses();
        let protocol = event.get_protocol();

        let flow_key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        // Use canonical key for bidirectional matching
        let canonical_key = flow_key.canonical();

        // Check max flows limit before creating new flow
        if !flows.contains_key(&canonical_key) && flows.len() >= self.max_flows {
            tracing::warn!("Max flows limit reached, cannot create new flow");
            // In production, implement LRU eviction here
            return;
        }

        // Get or create flow
        let flow = flows.entry(canonical_key).or_insert_with(|| {
            FlowRecord::new(event)
        });

        // Add packet to flow
        flow.add_packet(event);
    }

    /// Export and remove expired flows
    pub fn export_expired_flows(&self) -> Vec<FlowRecord> {
        let mut flows = self.flows.write();
        let mut expired = Vec::new();

        // Find expired flows
        let expired_keys: Vec<FlowKey> = flows
            .iter()
            .filter(|(_, flow)| flow.is_expired(self.flow_timeout))
            .map(|(key, _)| key.clone())
            .collect();

        // Remove and collect expired flows
        for key in expired_keys {
            if let Some(flow) = flows.remove(&key) {
                expired.push(flow);
            }
        }

        // Call completion callback
        if let Some(callback) = &self.on_flow_complete {
            for flow in &expired {
                callback(flow.clone());
            }
        }

        expired
    }

    /// Force export all flows (for shutdown)
    pub fn export_all_flows(&self) -> Vec<FlowRecord> {
        let mut flows = self.flows.write();
        let all_flows: Vec<FlowRecord> = flows.drain().map(|(_, flow)| flow).collect();

        // Call completion callback
        if let Some(callback) = &self.on_flow_complete {
            for flow in &all_flows {
                callback(flow.clone());
            }
        }

        all_flows
    }

    /// Get current flow count
    pub fn flow_count(&self) -> usize {
        self.flows.read().len()
    }

    /// Get flow statistics
    pub fn stats(&self) -> FlowAggregatorStats {
        let flows = self.flows.read();
        let total_flows = flows.len();
        let total_packets: u64 = flows
            .values()
            .map(|f| f.forward.packets + f.backward.packets)
            .sum();

        FlowAggregatorStats {
            active_flows: total_flows,
            total_packets,
        }
    }

    /// Start periodic export task
    pub fn start_export_task(
        self: Arc<Self>,
        export_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(export_interval);
            loop {
                interval.tick().await;
                let expired = self.export_expired_flows();
                if !expired.is_empty() {
                    tracing::debug!("Exported {} expired flows", expired.len());
                }
            }
        })
    }
}

/// Flow aggregator statistics
#[derive(Debug, Clone)]
pub struct FlowAggregatorStats {
    pub active_flows: usize,
    pub total_packets: u64,
}

/// Flow exporter - extracts features and sends to inference service
pub struct FlowExporter {
    aggregator: Arc<FlowAggregator>,
}

impl FlowExporter {
    /// Create a new flow exporter
    pub fn new(aggregator: Arc<FlowAggregator>) -> Self {
        Self { aggregator }
    }

    /// Export flow with features
    pub fn export_flow(&self, flow: &FlowRecord) -> (FlowRecord, CicFeatures) {
        let features = CicFeatures::extract(flow);
        (flow.clone(), features)
    }

    /// Export all expired flows with features
    pub fn export_expired_flows(&self) -> Vec<(FlowRecord, CicFeatures)> {
        let expired_flows = self.aggregator.export_expired_flows();
        expired_flows
            .iter()
            .map(|flow| self.export_flow(flow))
            .collect()
    }
}