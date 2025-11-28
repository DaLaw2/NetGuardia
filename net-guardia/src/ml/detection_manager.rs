use super::alerts::AlertManager;
use super::flow_aggregator::FlowAggregator;
use super::flow_record::FlowRecord;
use super::inference_client::InferenceClient;
use common::model::event::Event;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// ML-based intrusion detection manager
pub struct DetectionManager {
    /// Flow aggregator
    flow_aggregator: Arc<FlowAggregator>,

    /// Inference client
    inference_client: Arc<InferenceClient>,

    /// Alert manager
    alert_manager: Arc<AlertManager>,

    /// Flow cache for IP lookups (flow_id -> FlowRecord)
    flow_cache: Arc<RwLock<HashMap<String, FlowRecord>>>,

    /// Configuration
    config: DetectionConfig,
}

/// Detection configuration
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Flow timeout (seconds)
    pub flow_timeout_secs: u64,

    /// Maximum flows to track
    pub max_flows: usize,

    /// Flow export interval (seconds)
    pub export_interval_secs: u64,

    /// Batch size for inference
    pub batch_size: usize,

    /// Maximum recent alerts to keep
    pub max_recent_alerts: usize,

    /// WebSocket ping interval (seconds)
    pub ws_ping_interval_secs: u64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            flow_timeout_secs: 120,
            max_flows: 100000,
            export_interval_secs: 10,
            batch_size: 50,
            max_recent_alerts: 1000,
            ws_ping_interval_secs: 30,
        }
    }
}

impl DetectionManager {
    /// Create a new detection manager
    pub async fn new(
        inference_url: String,
        config: DetectionConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create flow aggregator
        let flow_aggregator = Arc::new(FlowAggregator::new(
            Duration::from_secs(config.flow_timeout_secs),
            config.max_flows,
        ));

        // Create inference client
        let inference_client = Arc::new(InferenceClient::new(inference_url).await?);

        // Create alert manager
        let alert_manager = Arc::new(AlertManager::new(config.max_recent_alerts));

        // Create flow cache
        let flow_cache = Arc::new(RwLock::new(HashMap::new()));

        Ok(Self {
            flow_aggregator,
            inference_client,
            alert_manager,
            flow_cache,
            config,
        })
    }

    /// Start detection tasks
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        // Task 1: Periodic flow export and inference
        let flow_agg = self.flow_aggregator.clone();
        let inference = self.inference_client.clone();
        let _alert_mgr = self.alert_manager.clone();
        let flow_cache = self.flow_cache.clone();
        let batch_size = self.config.batch_size;
        let export_interval = Duration::from_secs(self.config.export_interval_secs);

        let export_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(export_interval);
            loop {
                interval.tick().await;

                // Export expired flows
                let expired = flow_agg.export_expired_flows();

                // Log current active flow count for debugging
                let active_count = flow_agg.flow_count();
                tracing::debug!("Active flows: {}, Expired flows: {}", active_count, expired.len());

                if expired.is_empty() {
                    continue;
                }

                tracing::info!("Exporting {} expired flows for ML inference (Active: {})", expired.len(), active_count);

                // Extract features and send to inference service in batches
                let mut batch = Vec::new();
                for flow in expired {
                    // Store flow in cache for later IP lookup
                    {
                        let mut cache = flow_cache.write();
                        cache.insert(flow.flow_id.clone(), flow.clone());
                    }

                    let features = super::features::CicFeatures::extract(&flow);
                    batch.push((flow, features));

                    if batch.len() >= batch_size {
                        // Send batch
                        if let Err(e) = inference.detect_batch(batch.clone()) {
                            tracing::error!("Failed to send batch for inference: {}", e);
                        }
                        batch.clear();
                    }
                }

                // Send remaining batch
                if !batch.is_empty() {
                    if let Err(e) = inference.detect_batch(batch) {
                        tracing::error!("Failed to send batch for inference: {}", e);
                    }
                }
            }
        });
        handles.push(export_handle);

        // Task 2: Process inference results and create alerts
        let inference_clone = self.inference_client.clone();
        let _alert_mgr_clone = self.alert_manager.clone();
        let flow_cache_clone = self.flow_cache.clone();

        inference_clone.on_result(move |result| {
            // Format confidence score
            let confidence_str = result.confidence
                .map(|c| format!("{:.2}", c))
                .unwrap_or_else(|| "N/A".to_string());

            // Look up flow information from cache
            let flow_info = {
                let cache = flow_cache_clone.read();
                cache.get(&result.flow_id).map(|flow| {
                    format!(
                        "{}:{} -> {}:{} (Protocol: {})",
                        flow.src_ip, flow.src_port,
                        flow.dst_ip, flow.dst_port,
                        flow.protocol
                    )
                })
            };

            let flow_details = flow_info.as_deref().unwrap_or("IP info unavailable");

            // Log detection results based on severity
            // Check if attack_type is BENIGN (case-insensitive)
            let is_benign = result.attack_type
                .as_ref()
                .map(|t| t.eq_ignore_ascii_case("BENIGN"))
                .unwrap_or(false);

            if is_benign {
                // BENIGN traffic - always log as info, even if is_anomaly is true
                tracing::info!(
                    "✓ Benign traffic: Flow: {} [{}], Confidence: {}",
                    result.flow_id,
                    flow_details,
                    confidence_str
                );
            } else if result.is_anomaly {
                // Actual anomaly/attack detected
                if let Some(ref attack_type) = result.attack_type {
                    tracing::warn!(
                        "🚨 ATTACK DETECTED! Type: {}, Flow: {} [{}], Confidence: {}",
                        attack_type,
                        result.flow_id,
                        flow_details,
                        confidence_str
                    );
                } else {
                    tracing::warn!(
                        "⚠️  ANOMALY DETECTED! Flow: {} [{}], Confidence: {}",
                        result.flow_id,
                        flow_details,
                        confidence_str
                    );
                }
            } else {
                // Not anomaly and not explicitly benign
                tracing::info!(
                    "✓ Normal traffic: Flow: {} [{}], Confidence: {}",
                    result.flow_id,
                    flow_details,
                    confidence_str
                );
            }
        });

        // Task 3: WebSocket ping
        let ping_handle = self
            .inference_client
            .clone()
            .start_ping_task(Duration::from_secs(self.config.ws_ping_interval_secs));
        handles.push(ping_handle);

        handles
    }

    /// Process a packet event
    pub fn process_event(&self, event: &Event) {
        self.flow_aggregator.process_event(event);
    }

    /// Get alert manager
    pub fn alert_manager(&self) -> Arc<AlertManager> {
        self.alert_manager.clone()
    }

    /// Get flow aggregator
    pub fn flow_aggregator(&self) -> Arc<FlowAggregator> {
        self.flow_aggregator.clone()
    }

    /// Get inference client
    pub fn inference_client(&self) -> Arc<InferenceClient> {
        self.inference_client.clone()
    }

    /// Shutdown and export all flows
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down detection manager...");

        // Export all remaining flows
        let flows = self.flow_aggregator.export_all_flows();
        tracing::info!("Exported {} remaining flows", flows.len());

        // TODO: Wait for inference results to complete
    }
}